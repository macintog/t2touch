// SPDX-License-Identifier: GPL-2.0-only
/* Observe whether T2 iBoot recovery appears on the internal BCE VHCI. */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define USB_ROOT "/sys/bus/usb/devices"

static bool read_id(const char *directory, const char *name, unsigned int *value)
{
	char path[PATH_MAX];
	char text[32];
	FILE *file;
	char *end = NULL;
	unsigned long parsed;

	if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
		return false;
	file = fopen(path, "re");
	if (!file)
		return false;
	if (!fgets(text, sizeof(text), file)) {
		fclose(file);
		return false;
	}
	fclose(file);
	errno = 0;
	parsed = strtoul(text, &end, 16);
	if (errno || end == text || parsed > 0xffff)
		return false;
	*value = (unsigned int)parsed;
	return true;
}

static bool find_recovery(char *resolved, size_t resolved_size, unsigned int *product)
{
	DIR *root = opendir(USB_ROOT);
	struct dirent *entry;
	bool found = false;

	if (!root)
		return false;
	while ((entry = readdir(root)) != NULL) {
		char directory[PATH_MAX];
		char real[PATH_MAX];
		unsigned int vendor;
		unsigned int candidate;

		if (entry->d_name[0] == '.')
			continue;
		if (snprintf(directory, sizeof(directory), "%s/%s", USB_ROOT,
			     entry->d_name) >= (int)sizeof(directory))
			continue;
		if (!read_id(directory, "idVendor", &vendor) || vendor != 0x05ac)
			continue;
		if (!read_id(directory, "idProduct", &candidate))
			continue;
		if (candidate != 0x1280 && candidate != 0x1281)
			continue;
		if (!realpath(directory, real))
			continue;
		*product = candidate;
		snprintf(resolved, resolved_size, "%s", real);
		found = true;
		break;
	}
	closedir(root);
	return found;
}

static double elapsed(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (double)(now.tv_sec - start->tv_sec) +
	       (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}

int main(int argc, char **argv)
{
	char *end = NULL;
	char boot_id[64] = "unknown";
	long seconds;
	FILE *log;
	FILE *boot_id_file;
	struct timespec start;
	bool booted_gone = false;
	bool nvme_gone = false;

	if (argc != 3) {
		fprintf(stderr, "usage: %s SECONDS LOG_PATH\n", argv[0]);
		return 2;
	}
	errno = 0;
	seconds = strtol(argv[1], &end, 10);
	if (errno || !end || *end || seconds < 5 || seconds > 3600) {
		fprintf(stderr, "invalid observation interval\n");
		return 2;
	}
	log = fopen(argv[2], "ae");
	if (!log) {
		perror("open log");
		return 1;
	}
	setvbuf(log, NULL, _IOLBF, 0);
	setvbuf(stdout, NULL, _IOLBF, 0);
	boot_id_file = fopen("/proc/sys/kernel/random/boot_id", "re");
	if (boot_id_file) {
		if (fgets(boot_id, sizeof(boot_id), boot_id_file))
			boot_id[strcspn(boot_id, "\r\n")] = '\0';
		fclose(boot_id_file);
	}
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		fprintf(stderr, "warning: mlockall failed: %s\n", strerror(errno));
	clock_gettime(CLOCK_MONOTONIC, &start);
	fprintf(log, "probe-start epoch=%ld boot_id=%s timeout=%ld\n",
		(long)time(NULL), boot_id, seconds);
	printf("T2 recovery USB observer started for %ld seconds\n", seconds);

	while (elapsed(&start) < (double)seconds) {
		char path[PATH_MAX];
		unsigned int product;

		if (find_recovery(path, sizeof(path), &product)) {
			bool internal = strstr(path, "/t2bce_vhci/") != NULL;
			fprintf(log, "recovery-seen pid=%04x internal_bce=%s path=%s\n",
				product, internal ? "yes" : "no", path);
			fflush(log);
			fsync(fileno(log));
			printf("recovery-seen pid=%04x internal_bce=%s path=%s\n",
			       product, internal ? "yes" : "no", path);
			fclose(log);
			return internal ? 0 : 3;
		}
		if (!booted_gone && access("/sys/bus/usb/devices/7-1/idProduct", F_OK) != 0) {
			booted_gone = true;
			fprintf(log, "booted-t2-usb-gone at=%.3f\n", elapsed(&start));
		}
		if (!nvme_gone && access("/sys/class/block/nvme0n1", F_OK) != 0) {
			nvme_gone = true;
			fprintf(log, "ans2-nvme-gone at=%.3f\n", elapsed(&start));
		}
		usleep(100000);
	}
	fprintf(log, "recovery-not-seen timeout=%ld booted_gone=%s nvme_gone=%s\n",
		seconds, booted_gone ? "yes" : "no", nvme_gone ? "yes" : "no");
	fflush(log);
	fsync(fileno(log));
	printf("recovery-not-seen timeout=%ld booted_gone=%s nvme_gone=%s\n",
	       seconds, booted_gone ? "yes" : "no", nvme_gone ? "yes" : "no");
	fclose(log);
	return 4;
}
