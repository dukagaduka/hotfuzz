cmake_minimum_required(VERSION 3.16)
project(hotfuzz LANGUAGES CXX)

# Создаем интерфейсную библиотеку (не компилируется в .a или .so)
add_library(hotfuzz INTERFACE)

# Указываем стандарт (для интерфейса используется INTERFACE вместо PUBLIC)
target_compile_features(hotfuzz INTERFACE cxx_std_23)

# Указываем пути к инклудам
target_include_directories(hotfuzz
    INTERFACE 
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann/include
)

if (WIN32)
    target_link_libraries(hotfuzz INTERFACE psapi)
endif()

# Исполняемый файл остается как был
add_executable(app main.cpp)
target_link_libraries(app PRIVATE hotfuzz)
