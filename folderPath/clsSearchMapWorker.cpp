#include "clsSearchMapWorker.h"

#include "newstructs.h"


#include <QMutexLocker>
#include <QThread>
#include <fstream>
#include <QDir>
#include <QThread>
#include <QByteArray>



clsSearchMapWorker::clsSearchMapWorker(QString fName) : fileName(fName),defaultPath("C:\\Users\\user\\Desktop\\parseSession\\"),isLastPacket(false),isNewPacket(false){

    this->startChrono = QDateTime::currentDateTime();


    QString dirPath = defaultPath + fileName;
    QDir dir(dirPath);

    if (dir.mkpath(dirPath)) {
        defaultPath = dirPath + "\\";

        qDebug() << "Directory created successfully: " << defaultPath;
    } else {

        qDebug() << "Failed to create directory: " << dirPath;
    }
}

clsSearchMapWorker::~clsSearchMapWorker(){
    QMutexLocker locker(&this->m);
    this->written.clear();
    this->sessionMap.clear();
    this->h.clear();
    this->p.clear();
    qDebug() << "Mutex serbest bırakıldı ve elemanlar temizlendi.";

}

void clsSearchMapWorker::controlMap(){
    qDebug() << "Control Map " ;
    while (true) {
        QThread::msleep(250);
        QMutexLocker locker(&this->m);
        qDebug() << this->h.size() ;
        if (!this->isNewPacket) {
            qDebug() << "Yeni paket degil devam";
            continue;
        }
        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {

            strSessıonInfo& sI = sIt.value();
            QString key = sIt.key();
            //std::cout << "Last process 1 " << std::endl;
            bool isneedsUpdate = (sI.packetCount >= 32 || this->isLastPacket);
            if (isneedsUpdate) {

                auto cIt = written.find(key);
                if (cIt != written.end()) {
                    if (cIt.value() != sI.packetCount) {
                        //std::cout << "Last process 3 " << std::endl;
                        printSesionExtracter(sI);
                        written[key] = sI.packetCount;
                        sIt = sessionMap.erase(sIt);
                    } else {
                        //std::cout << "Last process 4 " << std::endl;
                        sIt = sessionMap.erase(sIt);
                    }
                } else {
                    //std::cout << "Last process 5 " << std::endl;
                    printSesionExtracter(sI);
                    written[key] = sI.packetCount;
                    sIt = sessionMap.erase(sIt);
                }
            } else {
                //std::cout << "Last process 6 " << std::endl;
                sIt++;
            }

        }
        this->isNewPacket = false;
        locker.unlock();


        if (sessionMap.empty() && this->isLastPacket) {
            qDebug() << "Last process 8 " ;
            QDateTime eTime = QDateTime::currentDateTime();
            qint64 processTime = startChrono.secsTo(eTime);

            qDebug()  << this->fileName << " pcap dosyasinin session parse islemi "
                      << processTime << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() ;
            break;
        }

    }

    emit finished();

}

void clsSearchMapWorker::setisLastPacket(bool isLast){
    qDebug()<< "setisLastPacket";
    QMutexLocker locker(&this->m);
    this->isLastPacket = isLast;
    locker.unlock();

}

void clsSearchMapWorker::setPacketsInfo(const u_char *pkt_data, const pcap_pkthdr *hdr){
    QMutexLocker locker(&this->m);
    QVector<quint8> pData (pkt_data,pkt_data+hdr->len);

    this->p.push_back(pData);
    this->h.push_back(*hdr);

    // p == QVector<QVector<quint8>>
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::updateSessionMap(const QString &key, const strSessıonInfo &newMap){
    QMutexLocker locker(&this->m);

    this->sessionMap[key] = newMap;
    this->isNewPacket = true;
    locker.unlock();

}

void clsSearchMapWorker::printSessionInfo(QString ses, strSessıonInfo sI){
    //bu kullanılmıyor ihtiyaç olursa doldur
}

void clsSearchMapWorker::printSesionExtracter(strSessıonInfo sInfo){

    QString pcapName = this->defaultPath + "session_" + sInfo.protocol + "_" + QString::number(sInfo.streamIndex) + ".pcap";


    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == nullptr) {
        qDebug() << "Pcap dosya oluşturma hatası: " << pcap_geterr(handle) ;
    }

    pcap_dumper_t* d = pcap_dump_open(handle, pcapName.toUtf8().constData());
    if (d == nullptr) {
        qDebug() << "Pcap dosya açma hatası: " << pcap_geterr(handle) ;
        pcap_close(handle);
    }

    for (const auto& i : sInfo.packetIndex) {
        const pcap_pkthdr& header = this->h[i-1];
        const QVector<quint8>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d), &header, packet.data());
    }


    pcap_dump_close(d);
    pcap_close(handle);

}
