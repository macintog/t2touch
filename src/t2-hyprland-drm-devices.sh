# SPDX-License-Identifier: GPL-2.0-only
# Exclude boot-framebuffer DRM devices when native DRM drivers are available.
# Prefer a GPU with a connected internal panel; retain other native GPUs.
# Preserve an explicit operator selection.
if [ -z "${AQ_DRM_DEVICES+x}" ]; then
    t2_drm_primary=
    t2_drm_external=
    t2_drm_others=
    t2_drm_fallback=no
    t2_drm_connected=no
    for t2_drm_entry in /sys/class/drm/card[0-9]*; do
        t2_drm_name=${t2_drm_entry##*/}
        case ${t2_drm_name#card} in ''|*[!0-9]*) continue ;; esac
        [ -c "/dev/dri/$t2_drm_name" ] || continue
        t2_drm_driver=$(readlink -f "$t2_drm_entry/device/driver" 2>/dev/null) || continue
        case ${t2_drm_driver##*/} in
            simple-framebuffer|simpledrm|efifb|vesafb)
                t2_drm_fallback=yes
                continue
                ;;
        esac
        [ -n "$t2_drm_driver" ] && [ -d "$t2_drm_driver" ] || continue
        t2_drm_has_display=no
        for t2_drm_connector in "$t2_drm_entry"-*; do
            [ -r "$t2_drm_connector/status" ] || continue
            if [ "$(cat "$t2_drm_connector/status")" = connected ]; then
                t2_drm_connected=yes
                t2_drm_has_display=yes
            fi
        done
        t2_drm_internal=no
        for t2_drm_connector in "$t2_drm_entry"-eDP-* "$t2_drm_entry"-LVDS-* "$t2_drm_entry"-DSI-*; do
            [ -r "$t2_drm_connector/status" ] || continue
            if [ "$(cat "$t2_drm_connector/status")" = connected ]; then
                t2_drm_internal=yes
                break
            fi
        done
        if [ "$t2_drm_internal" = yes ]; then
            t2_drm_primary="${t2_drm_primary:+$t2_drm_primary:}/dev/dri/$t2_drm_name"
        elif [ "$t2_drm_has_display" = yes ]; then
            t2_drm_external="${t2_drm_external:+$t2_drm_external:}/dev/dri/$t2_drm_name"
        else
            t2_drm_others="${t2_drm_others:+$t2_drm_others:}/dev/dri/$t2_drm_name"
        fi
    done
    t2_drm_selected=
    for t2_drm_group in "$t2_drm_primary" "$t2_drm_external" "$t2_drm_others"; do
        [ -z "$t2_drm_group" ] || t2_drm_selected="${t2_drm_selected:+$t2_drm_selected:}$t2_drm_group"
    done
    if [ "$t2_drm_fallback" = yes ] && [ "$t2_drm_connected" = yes ] && [ -n "$t2_drm_selected" ]; then
        export AQ_DRM_DEVICES="$t2_drm_selected"
    fi
    unset t2_drm_primary t2_drm_others t2_drm_fallback t2_drm_connected t2_drm_entry t2_drm_name
    unset t2_drm_external t2_drm_has_display t2_drm_group
    unset t2_drm_driver t2_drm_internal t2_drm_connector t2_drm_selected
fi
