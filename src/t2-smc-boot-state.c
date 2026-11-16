// SPDX-License-Identifier: GPL-2.0-only
/*
 * Publish the typed T2 SEP versioned-app boot state through the macsmc
 * character device (/dev/smc).
 *
 * Linux 7.3 replaced applesmc with the macsmc MFD stack on T2 Macs, so the
 * applesmc boot-state publisher (linux_native/patches/
 * applesmc-t2-sep-boot-state.patch) cannot load there. This helper performs
 * the same one-shot EFMV/EFMS/EFBS transaction from userspace and records the
 * result in the same vocabulary the applesmc sysfs attribute used.
 *
 *   t2-smc-boot-state --probe      read-only: report key info and EFMV state
 *   t2-smc-boot-state --publish    perform the one-shot transaction
 *
 * The transaction must run at most once per boot. A commit-uncertain result
 * must not be retried before the next reboot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

/* Mirror of include/linux/mfd/macsmc.h (not exported as UAPI). */
typedef uint32_t smc_key;

struct apple_smc_key_info {
	uint32_t type_code;
	uint8_t size;
	uint8_t flags;
};

struct ioctl_smc_rw_payload {
	smc_key key;
	size_t size;
	uint8_t buf[32];
};

struct ioctl_smc_info_payload {
	smc_key key;
	struct apple_smc_key_info info;
};

#define APPLE_SMC_MAGIC 'S'
#define IOCTL_SMC_READ          _IOWR(APPLE_SMC_MAGIC, 1, struct ioctl_smc_rw_payload)
#define IOCTL_SMC_WRITE         _IOW(APPLE_SMC_MAGIC, 2, struct ioctl_smc_rw_payload)
#define IOCTL_SMC_GET_KEY_INFO  _IOWR(APPLE_SMC_MAGIC, 4, struct ioctl_smc_info_payload)

#define APPLE_SMC_READABLE 0x80
#define APPLE_SMC_WRITABLE 0x40

#define KEY(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
			 ((uint32_t)(c) << 8) | (uint32_t)(d))
#define KEY_EFMV KEY('E', 'F', 'M', 'V')
#define KEY_EFMS KEY('E', 'F', 'M', 'S')
#define KEY_EFBS KEY('E', 'F', 'B', 'S')

#define EFMV_LENGTH        32
#define EFM_STATE_LENGTH   1
#define EFBS_COMMIT        0x11
#define EFMS_TIMEOUT_MSECS 40000
#define EFMS_POLL_MSECS    10

#define SMC_DEVICE   "/dev/smc"
#define RESULT_DIR   "/run/t2touch"
#define RESULT_PATH  RESULT_DIR "/t2_sep_boot_state"
#define LOCK_PATH    RESULT_DIR "/t2_sep_boot_state.lock"
#define DMI_BIOS     "/sys/class/dmi/id/bios_version"

static int smc_fd = -1;

static int smc_info(smc_key key, struct apple_smc_key_info *info)
{
	struct ioctl_smc_info_payload p = { .key = key };

	if (ioctl(smc_fd, IOCTL_SMC_GET_KEY_INFO, &p) < 0)
		return -errno;
	*info = p.info;
	return 0;
}

static int smc_read(smc_key key, void *buf, size_t size)
{
	struct ioctl_smc_rw_payload p = { .key = key, .size = size };

	if (size > sizeof(p.buf))
		return -EINVAL;
	if (ioctl(smc_fd, IOCTL_SMC_READ, &p) < 0)
		return -errno;
	memcpy(buf, p.buf, size);
	return 0;
}

static int smc_write(smc_key key, const void *buf, size_t size)
{
	struct ioctl_smc_rw_payload p = { .key = key, .size = size };

	if (size > sizeof(p.buf))
		return -EINVAL;
	memcpy(p.buf, buf, size);
	if (ioctl(smc_fd, IOCTL_SMC_WRITE, &p) < 0)
		return -errno;
	return 0;
}

/* Same parser as the applesmc patch: "... (iBridge: a.b.c.d.e,f)" */
static int parse_bridge_version(uint32_t v[6])
{
	char bios[256] = { 0 };
	const char *ibridge;
	char trailing;
	FILE *f = fopen(DMI_BIOS, "re");

	if (!f)
		return -ENODEV;
	if (!fgets(bios, sizeof(bios), f)) {
		fclose(f);
		return -ENODEV;
	}
	fclose(f);
	bios[strcspn(bios, "\n")] = '\0';

	ibridge = strstr(bios, "(iBridge: ");
	if (!ibridge)
		return -ENODEV;
	if (sscanf(ibridge, "(iBridge: %u.%u.%u.%u.%u,%u)%c",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &trailing) != 6)
		return -EINVAL;
	return 0;
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static int record(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int record(const char *fmt, ...)
{
	char tmp[] = RESULT_DIR "/.t2_sep_boot_state.XXXXXX";
	va_list ap;
	FILE *f;
	int fd;

	if (mkdir(RESULT_DIR, 0755) < 0 && errno != EEXIST)
		return -errno;
	fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;
	fchmod(fd, 0644);
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmp);
		return -errno;
	}
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	if (fclose(f) != 0 || rename(tmp, RESULT_PATH) < 0) {
		unlink(tmp);
		return -errno;
	}
	return 0;
}

static void dump(const char *label, const uint8_t *b, size_t n)
{
	printf("%s:", label);
	for (size_t i = 0; i < n; i++)
		printf(" %02x", b[i]);
	printf("\n");
}

static int efmv_is_pristine(const uint8_t *efmv)
{
	if (efmv[0] != 0xfe)
		return 0;
	for (size_t i = 1; i < EFMV_LENGTH; i++)
		if (efmv[i])
			return 0;
	return 1;
}

static int check_keys(int verbose)
{
	static const struct { smc_key key; const char *name; uint8_t size; } want[] = {
		{ KEY_EFMV, "EFMV", EFMV_LENGTH },
		{ KEY_EFMS, "EFMS", EFM_STATE_LENGTH },
		{ KEY_EFBS, "EFBS", EFM_STATE_LENGTH },
	};

	for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
		struct apple_smc_key_info info = { 0 };
		int ret = smc_info(want[i].key, &info);

		if (ret) {
			fprintf(stderr, "%s: key info failed: %s\n", want[i].name, strerror(-ret));
			return ret;
		}
		if (verbose)
			printf("%s: size=%u flags=0x%02x type=%c%c%c%c\n", want[i].name,
			       info.size, info.flags,
			       (info.type_code >> 24) & 0xff, (info.type_code >> 16) & 0xff,
			       (info.type_code >> 8) & 0xff, info.type_code & 0xff);
		if (info.size != want[i].size) {
			fprintf(stderr, "%s: unexpected size %u (want %u)\n",
				want[i].name, info.size, want[i].size);
			return -EPROTO;
		}
	}
	return 0;
}

static int do_probe(void)
{
	uint8_t efmv[EFMV_LENGTH], efms = 0;
	uint32_t v[6];
	int ret;

	ret = parse_bridge_version(v);
	if (ret) {
		fprintf(stderr, "bridgeOS version from DMI: %s\n", strerror(-ret));
		return 1;
	}
	printf("bridgeOS version: %u.%u.%u.%u.%u,%u\n", v[0], v[1], v[2], v[3], v[4], v[5]);

	if (check_keys(1))
		return 1;
	ret = smc_read(KEY_EFMV, efmv, sizeof(efmv));
	if (ret) {
		fprintf(stderr, "EFMV read failed: %s\n", strerror(-ret));
		return 1;
	}
	dump("EFMV", efmv, sizeof(efmv));
	ret = smc_read(KEY_EFMS, &efms, 1);
	if (ret) {
		fprintf(stderr, "EFMS read failed: %s\n", strerror(-ret));
		return 1;
	}
	printf("EFMS: %02x\n", efms);
	printf("state: %s\n", efmv_is_pristine(efmv) ?
	       "pristine (boot state not yet published this boot)" :
	       "already published this boot");
	return 0;
}

static int do_publish(unsigned int epoch_major, unsigned int epoch_minor)
{
	uint8_t efmv[EFMV_LENGTH] = { 0 };
	uint8_t efms = 0;
	const uint8_t efbs = EFBS_COMMIT;
	uint32_t v[6];
	struct timespec start, now, nap = { 0, EFMS_POLL_MSECS * 1000000L };
	int lock_fd, ret;

	if (mkdir(RESULT_DIR, 0755) < 0 && errno != EEXIST) {
		perror(RESULT_DIR);
		return 1;
	}
	/* Once per boot: /run is tmpfs, so an existing result means we ran. */
	lock_fd = open(LOCK_PATH, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		fprintf(stderr, "another publisher is running\n");
		return 1;
	}
	if (access(RESULT_PATH, F_OK) == 0) {
		fprintf(stderr, "boot state already attempted this boot; see %s\n", RESULT_PATH);
		return 0;
	}

	if (epoch_major > 0xff || epoch_minor > 0xff) {
		record("rejected");
		return 1;
	}
	ret = parse_bridge_version(v);
	if (ret) {
		record("rejected");
		fprintf(stderr, "bridgeOS version from DMI: %s\n", strerror(-ret));
		return 1;
	}
	ret = check_keys(0);
	if (ret) {
		record(ret == -EPROTO ? "rejected" : "failed");
		return 1;
	}
	ret = smc_read(KEY_EFMV, efmv, sizeof(efmv));
	if (ret) {
		record("failed");
		fprintf(stderr, "EFMV read failed: %s\n", strerror(-ret));
		return 1;
	}
	if (!efmv_is_pristine(efmv)) {
		record("rejected");
		fprintf(stderr, "EFMV is not pristine; boot state was already published\n");
		return 1;
	}

	memset(efmv, 0, sizeof(efmv));
	efmv[0] = 1;
	efmv[1] = epoch_major;
	efmv[2] = epoch_minor;
	for (int i = 0; i < 6; i++)
		put_le32(&efmv[4 + i * 4], v[i]);

	/* From here on, any failure leaves the outcome uncertain. */
	if ((ret = smc_write(KEY_EFMV, efmv, sizeof(efmv))) ||
	    (ret = smc_write(KEY_EFMS, &efms, EFM_STATE_LENGTH)) ||
	    (ret = smc_write(KEY_EFBS, &efbs, EFM_STATE_LENGTH)))
		goto uncertain;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		ret = smc_read(KEY_EFMS, &efms, EFM_STATE_LENGTH);
		if (ret)
			goto uncertain;
		if (efms)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000 >= EFMS_TIMEOUT_MSECS) {
			ret = -ETIMEDOUT;
			goto uncertain;
		}
		nanosleep(&nap, NULL);
	}

	record("response-received:%u", efms);
	printf("received T2 SEP boot-policy response %u for bridgeOS %u.%u.%u.%u.%u,%u epoch %u.%u\n",
	       efms, v[0], v[1], v[2], v[3], v[4], v[5], epoch_major, epoch_minor);
	return 0;

uncertain:
	record("commit-uncertain");
	fprintf(stderr, "T2 SEP boot-state transaction outcome is uncertain (%s); do not retry before reboot\n",
		strerror(-ret));
	return 1;
}

static void usage(FILE *out)
{
	fprintf(out, "Usage: t2-smc-boot-state --probe\n"
		     "       t2-smc-boot-state --publish [--epoch-major N] [--epoch-minor N]\n");
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "probe", no_argument, NULL, 'p' },
		{ "publish", no_argument, NULL, 'P' },
		{ "epoch-major", required_argument, NULL, 'M' },
		{ "epoch-minor", required_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 }
	};
	unsigned long major = 1, minor = 0;
	int mode = 0, c;
	char *end;
	const char *env;

	/* Defaults match the applesmc modprobe options; /etc/t2-touchid.conf
	 * (loaded by the unit as EnvironmentFile) may override them. */
	if ((env = getenv("T2_TOUCHID_SEP_EPOCH_MAJOR")) && *env) {
		errno = 0;
		major = strtoul(env, &end, 0);
		if (errno || *end) { fprintf(stderr, "bad T2_TOUCHID_SEP_EPOCH_MAJOR\n"); return 2; }
	}
	if ((env = getenv("T2_TOUCHID_SEP_EPOCH_MINOR")) && *env) {
		errno = 0;
		minor = strtoul(env, &end, 0);
		if (errno || *end) { fprintf(stderr, "bad T2_TOUCHID_SEP_EPOCH_MINOR\n"); return 2; }
	}

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 'p': case 'P':
			if (mode) { usage(stderr); return 2; }
			mode = c;
			break;
		case 'M': case 'm':
			errno = 0;
			if (c == 'M')
				major = strtoul(optarg, &end, 0);
			else
				minor = strtoul(optarg, &end, 0);
			if (errno || *end || !*optarg) { usage(stderr); return 2; }
			break;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}
	if (!mode || optind != argc) {
		usage(stderr);
		return 2;
	}

	smc_fd = open(SMC_DEVICE, O_RDWR | O_CLOEXEC);
	if (smc_fd < 0) {
		fprintf(stderr, "%s: %s\n", SMC_DEVICE, strerror(errno));
		if (mode == 'P')
			record("not-applicable");
		return 1;
	}
	return mode == 'p' ? do_probe() : do_publish(major, minor);
}
