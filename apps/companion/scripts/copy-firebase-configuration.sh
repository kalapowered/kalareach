#!/bin/bash
# Puts Firebase's configuration into the application being built.
#
# The configuration belongs to the account that owns the Firebase project, not to this repository,
# so it is copied from the path `KR_GOOGLE_SERVICE_INFO` names. A debug build without the variable
# runs and leaves Firebase alone; a build told of a file that is not there fails, since a mistyped
# path would otherwise give a build that quietly cannot receive a notification; and a release build
# without the variable fails, because a release that cannot receive a notification is not one to
# ship. A copy an earlier build left in the product is removed first, so a build without the file
# never carries another's. Xcode runs this as a build phase with `TARGET_BUILD_DIR`,
# `UNLOCALIZED_RESOURCES_FOLDER_PATH` and `CONFIGURATION` set.
set -eu
destination="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/GoogleService-Info.plist"
rm -f "${destination}"
if [ -n "${KR_GOOGLE_SERVICE_INFO:-}" ]; then
    if [ ! -f "${KR_GOOGLE_SERVICE_INFO}" ]; then
        echo "error: KR_GOOGLE_SERVICE_INFO names ${KR_GOOGLE_SERVICE_INFO}, which is not a file" >&2
        exit 1
    fi
    cp "${KR_GOOGLE_SERVICE_INFO}" "${destination}"
elif [ "${CONFIGURATION}" = "release" ]; then
    echo "error: a release build needs KR_GOOGLE_SERVICE_INFO to name a GoogleService-Info.plist" >&2
    exit 1
else
    echo "note: no GoogleService-Info.plist named by KR_GOOGLE_SERVICE_INFO, so Firebase is left alone"
fi
