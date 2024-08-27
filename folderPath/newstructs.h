#ifndef NEWSTRUCTS_H
#define NEWSTRUCTS_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QStringList>




struct strPacketInfo{
    QString sourceIP;
    QString destIP;
    QString sourceMac;
    QString destMac;

    uint16_t sourcePort;
    uint16_t destPort;

    QString protocol ;
    QString timestamp ;
    int packetLen;
    QString message ;
    QString smtpSender;
    QString smtpRecipient;
};

struct strSessıonInfo{
    QString sourceIP;
    QString destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    int streamIndex;
    int packetCount;
    int packetsLen;
    int sourceTodest;
    int sourceTodestLen;
    int destToSource;
    int destToSourceLen;
    QString startTime;
    QString endTime;
    QVector<int> packetIndex;
    QStringList messages;

    QString protocol;
    QString smtpSender;
    QString smtpRecipient;
};


#endif // NEWSTRUCTS_H
