add_custom_command(
    OUTPUT ${PROJECT_SOURCE_DIR}/src/cmd_generated.h
    COMMAND flatcc --outfile ${PROJECT_SOURCE_DIR}/src/cmd_generated.h -a ${PROJECT_SOURCE_DIR}/src/cmd.fbs
    COMMENT "generating cmd_generated.h ..."
)

include_directories (
    "${PROJECT_SOURCE_DIR}/external/include"
    "${PROJECT_SOURCE_DIR}/src"
)

link_directories(
    "${PROJECT_SOURCE_DIR}/external/lib"
)

add_executable(elatun
    cmd_generated.h
    cmd/bind.c
    cmd/unbind.c
    cmd/services.c
    cmd/open.c
    cmd/ps.c
    cmd/close.c
    cmd/info.c
    cmd.c
    config.c
    packet.c
    socket.c
    tunnel.c
    main.c
)

target_link_libraries(elatun
    elacommon
    elacarrier
    elasession
    flatccrt
    confuse
)

if (SECURE_TUNNEL_INSTALL)
    install(TARGETS elatun DESTINATION bin)
endif()
