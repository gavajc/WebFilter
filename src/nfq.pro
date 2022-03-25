TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    nfqueue.cpp \
    nfqfilter.cpp \
    nfqpolicy.cpp \
    nfqdns.cpp \
    nfqlog.cpp \
    nfqreport.cpp

HEADERS += \
    nfqueue.h \
    StrUtils.h \
    SysUtils.h \
    nfqfilter.h \
    nfqinfo.h \
    nfqdns.h \
    nfqdefs.h \
    nfqbwth.h \
    nfqnetp.h \
    nfqpolicy.h \
    nfqdom.h \
    tld-canon.h \
    nfqlog.h \
    nfqreport.h

LIBS += -pthread -lnfnetlink -lmnl -lnetfilter_queue -levent
