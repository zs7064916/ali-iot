# Copyright (C) 2018 RDA Technologies Limited and/or its affiliates("RDA").
# All rights reserved.
#
# This software is supplied "AS IS" without any warranties.
# RDA assumes no responsibility or liability for the use of the software,
# conveys no license or title under any patent, copyright, or mask work
# right to the product. RDA reserves the right to make changes in the
# software without notification.  RDA also make no representation or
# warranty that such application will be suitable for the specified use
# without further testing or modification.

aux_source_directory(./eng/certs CERTS)
aux_source_directory(./eng/dev_sign DEV_SIGN)
aux_source_directory(./eng/infra INFRA)
aux_source_directory(./eng/mqtt MQTT)
aux_source_directory(./eng/wrappers WRAPPERS)

set(target iotkit)
add_library(${target} STATIC
    ${CERTS}
    ${DEV_SIGN}
    ${INFRA}
    ${MQTT}
    ${WRAPPERS}
)

set_target_properties(${target} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${out_lib_dir})
target_include_directories(${target} PUBLIC eng eng/dev_sign eng/infra eng/mqtt eng/wrappers)
