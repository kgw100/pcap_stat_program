TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cpp/main.cpp \
        cpp/stat_func.cpp \
        cpp/stat_ptcs.cpp \
        cpp/util.cpp
LIBS += -lpcap
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    header/pcap_stat.h \
    header/sfdafx.h \
    header/stat_func.h \
    header/stat_ptcs.h \
    header/util.h
