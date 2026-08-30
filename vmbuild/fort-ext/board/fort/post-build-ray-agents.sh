#!/bin/sh
# Ray invokes several .py files directly via `python3 <path>/foo.py` rather
# than via `-m module`, so it needs the literal .py source to exist.
# BR2_PACKAGE_PYTHON3_PYC_ONLY strips all .py source target-wide, so restore
# these entry-point scripts from the original wheel afterward.
set -eu

target_dir="${1:?missing target dir}"
output_dir=$(cd "${target_dir}/.." && pwd)

wheel=$(find "${output_dir}/build"/python-ray-*/wheels -maxdepth 1 -name "ray-*.whl" 2>/dev/null | head -1)
if [ -z "${wheel}" ]; then
    echo "post-build-ray-agents: ray wheel not found, skipping" >&2
    exit 0
fi

site_packages="${target_dir}/usr/lib/python3.14/site-packages"

restore() {
    unzip -p "${wheel}" "$1" > "${site_packages}/$1"
}

# Per-node agents (spawned by raylet on every worker and head node)
restore ray/dashboard/agent.py
restore ray/_private/runtime_env/agent/main.py

# Task worker (spawned by raylet to execute remote functions)
restore ray/_private/workers/default_worker.py

# Log monitor and process reaper (spawned by ray start on each node)
restore ray/_private/log_monitor.py
restore ray/_private/ray_process_reaper.py

# Dashboard (spawned on the head node only)
restore ray/dashboard/dashboard.py

# scipy.libs bundles libgfortran/libquadmath/openblas. auditwheel sets RUNPATH
# on the top-level extension .so files but not on the bundled libgfortran, so
# the loader can't find libquadmath as a transitive dep. Patch libgfortran's
# RUNPATH so it can find libquadmath in the same scipy.libs directory.
SCIPY_LIBS="${site_packages}/scipy.libs"
PATCHELF="$(dirname "${target_dir}")/host/bin/patchelf"
SCIPY_LIBS_RUNPATH="/usr/lib/python3.14/site-packages/scipy.libs"
for lib in "${SCIPY_LIBS}"/libgfortran-*.so.*; do
    [ -f "${lib}" ] || continue
    "${PATCHELF}" --set-rpath "${SCIPY_LIBS_RUNPATH}" "${lib}"
done
