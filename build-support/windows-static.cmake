# Loaded immediately after project(), before dependencies are discovered.
# MSYS2 supplies both DLL import libraries and real static libraries.
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
cmake_policy(SET CMP0079 NEW)
add_link_options(-static -static-libgcc -static-libstdc++)
add_compile_definitions(GNUTLS_INTERNAL_BUILD)

function(tigervncs_static_dependencies)
  execute_process(
    COMMAND "${PKG_CONFIG_EXECUTABLE}" --static --libs-only-l gnutls
    OUTPUT_VARIABLE private_libraries
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
  separate_arguments(private_libraries UNIX_COMMAND "${private_libraries}")
  # Resolve transitive dependencies, including cyclic references, after the
  # libraries selected by the upstream find modules.
  foreach(binary vncviewer vncviewer_manager_test vncviewer_lifecycle_test clientcompatibility apple_session_probe)
    if(TARGET ${binary})
      target_link_libraries(${binary} PRIVATE
        -Wl,--start-group ${private_libraries} -Wl,--end-group)
    endif()
  endforeach()
endfunction()

cmake_language(DEFER CALL tigervncs_static_dependencies)
