if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  message(FATAL_ERROR "cmake must be invoked with the top level directory")
endif()

include(GoogleTest)

# Google Test requires a new C++ standard
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17")
endif()

enable_testing()

add_executable(clientcompatibility clientcompatibility.cxx)
target_link_libraries(clientcompatibility PRIVATE rfbclient GTest::gtest_main)
gtest_discover_tests(clientcompatibility)

add_executable(scalegeometry scalegeometry.cxx)
target_link_libraries(scalegeometry PRIVATE core GTest::gtest_main)
gtest_discover_tests(scalegeometry)

add_executable(portableconfig portableconfig.cxx ../../vncviewer/PortableConfig.cxx)
target_include_directories(portableconfig SYSTEM PRIVATE ${FLTK_INCLUDE_DIR})
target_link_libraries(portableconfig PRIVATE core GTest::gtest_main jsoncpp_static ${FLTK_LIBRARIES})
gtest_discover_tests(portableconfig)

if(WIN32)
  add_executable(connection_fixture EXCLUDE_FROM_ALL ../integration/connection_fixture.cxx
    ../../vncviewer/ConnectionStore.cxx ../../vncviewer/CredentialVault.cxx
    ../../vncviewer/PortableConfig.cxx)
  target_include_directories(connection_fixture SYSTEM PRIVATE ${FLTK_INCLUDE_DIR})
  target_link_libraries(connection_fixture PRIVATE network core jsoncpp_static
    ${FLTK_LIBRARIES} bcrypt crypt32)
  add_executable(connectionstore connectionstore.cxx ../../vncviewer/ConnectionStore.cxx
    ../../vncviewer/CredentialVault.cxx ../../vncviewer/PortableConfig.cxx
    ../../vncviewer/ConnectionTree.cxx)
  target_include_directories(connectionstore SYSTEM PRIVATE ${FLTK_INCLUDE_DIR})
  target_link_libraries(connectionstore PRIVATE network core GTest::gtest_main jsoncpp_static
    ${FLTK_LIBRARIES} bcrypt crypt32)
  gtest_discover_tests(connectionstore)
  add_executable(scaled_surface scaled_surface.cxx
    ../../vncviewer/Surface.cxx ../../vncviewer/Surface_Win32.cxx)
  target_include_directories(scaled_surface SYSTEM PRIVATE ${FLTK_INCLUDE_DIR})
  target_link_libraries(scaled_surface PRIVATE core GTest::gtest_main ${FLTK_LIBRARIES} msimg32)
  gtest_discover_tests(scaled_surface)
endif()

include_directories(${CMAKE_SOURCE_DIR}/vncviewer)

add_executable(configargs configargs.cxx)
target_link_libraries(configargs PRIVATE rfb GTest::gtest_main)
gtest_discover_tests(configargs)

add_executable(conv conv.cxx)
target_link_libraries(conv PRIVATE rfb GTest::gtest_main)
gtest_discover_tests(conv)

add_executable(convertlf convertlf.cxx)
target_link_libraries(convertlf PRIVATE core GTest::gtest_main)
gtest_discover_tests(convertlf)

add_executable(gesturehandler gesturehandler.cxx ../../vncviewer/GestureHandler.cxx)
target_link_libraries(gesturehandler PRIVATE core GTest::gtest_main)
gtest_discover_tests(gesturehandler)

add_executable(hostport hostport.cxx)
target_link_libraries(hostport PRIVATE network GTest::gtest_main)
gtest_discover_tests(hostport)

add_executable(parameters parameters.cxx)
target_link_libraries(parameters PRIVATE core GTest::gtest_main)
gtest_discover_tests(parameters)

add_executable(pixelformat pixelformat.cxx)
target_link_libraries(pixelformat PRIVATE rfb GTest::gtest_main)
gtest_discover_tests(pixelformat)

add_executable(shortcuthandler shortcuthandler.cxx ../../vncviewer/ShortcutHandler.cxx)
target_link_libraries(shortcuthandler PRIVATE core GTest::gtest_main)
gtest_discover_tests(shortcuthandler)

add_executable(unicode unicode.cxx)
target_link_libraries(unicode PRIVATE core GTest::gtest_main)
gtest_discover_tests(unicode)

add_executable(emulatemb emulatemb.cxx ../../vncviewer/EmulateMB.cxx)
target_link_libraries(emulatemb PRIVATE core GTest::gtest_main)
gtest_discover_tests(emulatemb)

if(ENABLE_H264)
  add_executable(h264decoder h264decoder.cxx)
  target_link_libraries(h264decoder PRIVATE rfbclient GTest::gtest_main)
  gtest_discover_tests(h264decoder)
endif()
