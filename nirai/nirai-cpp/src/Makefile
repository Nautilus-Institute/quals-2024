
all: nirai-cpp-flag1 nirai-cpp-flag4

nirai-cpp-flag1: main.cpp \
    webui.cpp \
    utils.cpp
	g++ -O2 main.cpp webui.cpp utils.cpp -DNIRAI_FLAG_1 \
        -I../../libtorrent/include/ \
        -std=c++17 -ltorrent-rasterbar -L../../libtorrent/build \
        -o nirai-cpp-flag1
	strip --strip-all nirai-cpp-flag1

nirai-cpp-flag4: main.cpp \
    webui.cpp \
    utils.cpp
	g++ -O2 main.cpp webui.cpp utils.cpp -DNIRAI_FLAG_4 \
        -I../../libtorrent/include/ \
        -std=c++17 -ltorrent-rasterbar -L../../libtorrent/build \
        -o nirai-cpp-flag4
	strip --strip-all nirai-cpp-flag4

