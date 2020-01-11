TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cpp/main.cpp \
        cpp/stat.cpp \
        cpp/util.cpp
LIBS += -lpcap
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    header/sfdafx.h \
    header/stat.h \
    header/util.h
