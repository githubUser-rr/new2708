#include "clsPacketOperation.h"
#include "MoveWorker.h"


#include <QString>
#include <QThread>
#include <pcap.h>
#include <filesystem>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDebug>
#include <QByteArray>
#include <QTextStream>


#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>



#define ETHERNET_HEADER_LENGTH 14




struct ipheader {
    quint8 iph_ihl : 4;   // IP başlığı uzunluğu
    quint8 iph_ver : 4;   // IP versiyonu
    quint8 iph_tos;       // Hizmet tipi
    quint16 iph_len;      // Toplam uzunluk
    quint16 iph_ident;    // Tanımlayıcı
    quint16 iph_flag : 3; // Bayraklar
    quint16 iph_offset : 13; // Parça offseti
    quint8 iph_ttl;       // Yaşam süresi
    quint8 iph_protocol;  // Protokol
    quint16 iph_chksum;   // Başlık checksum
    in_addr iph_sourceip; // Kaynak IP adresi
    in_addr iph_destip;   // Hedef IP adresi
};

struct ethHeader {
    quint8  destMac[6];
    quint8  sourceMac[6];
    quint16 eType; // Ethernet türü
};


struct tcphdr {
    quint16 th_sport;   // Kaynak port numarası
    quint16 th_dport;   // Hedef port numarası
    quint32 th_seq;     // Dizi numarası
    quint32 th_ack;     // Onay numarası
    quint8 th_offx2;    // Veri ofseti, rezerve edilmiş alanlar ve flags
    quint8 th_flags;    // Kontrol flagları
    quint16 th_win;     // Pencere boyutu
    quint16 th_sum;     // Checksum
    quint16 th_urp;     // Acil işlem göstergesi
};


struct udphdr {
    quint16 uh_sport;   // Kaynak port numarası
    quint16 uh_dport;   // Hedef port numarası
    quint16 uh_ulen;    // Toplam uzunluk
    quint16 uh_sum;     // Checksum
};




clsPacketOperation::clsPacketOperation(const QString &p) : filePath(p),handle(nullptr),defaultPath("C:\\Users\\user\\Desktop\\parseSession\\")
                                                        ,defaultCsvPath ("C:\\Users\\user\\Desktop\\csvOut\\"),defaultTxtPath ("C:\\Users\\user\\Desktop\\txtOut\\")
                                                        ,pCount(0),streamIndex(0),streamIndexUdp(0),objStartTime(QDateTime::currentDateTime()){
    qDebug() << "Cons !!" ;



    while(true){
        QFileInfo fInfo(filePath);
        QDateTime modifyDate = fInfo.lastModified();
        QDateTime currTime = QDateTime::currentDateTime();
        qint64 subSeconds = modifyDate.secsTo(currTime);


        if(subSeconds >= 4){
            qDebug() << "Simdiki zaman ile modify date farkı : " << subSeconds ;
            this->fileName = fInfo.fileName();
            this->directory = fInfo.path();
            break;
        }
        qDebug() << "Dosya yazma islemi devam ediyor , modify date  : " << subSeconds ;
        QThread::sleep(2);
    }

    try {
        QByteArray bArray = filePath.toUtf8();
        const char* pFileName = bArray.constData();
        this->handle = pcap_open_offline(pFileName,this->errbuf);
        if (this->handle == NULL) {
            qWarning() <<  "PCAP dosyasi acilamadi : " << this->errbuf ;

            controlOpen = false;
        }
        else {
            qDebug() << "Basarili" ;
            controlOpen = true;


            //SearchMapWorker , qt göre düzenle
            QString str = this->fileName.left(fileName.lastIndexOf('.'));
            this->clsSMap = new clsSearchMapWorker(str);
            QThread* cThread = new QThread;
            this->clsSMap->moveToThread(cThread);

            QObject::connect(cThread,&QThread::started,clsSMap,&clsSearchMapWorker::controlMap);
            QObject::connect(clsSMap,&clsSearchMapWorker::finished,cThread,&QThread::quit);
            QObject::connect(clsSMap,&clsSearchMapWorker::finished,clsSMap,&clsSearchMapWorker::deleteLater);
            QObject::connect(cThread,&QThread::finished,cThread,&QThread::deleteLater);
            cThread->start();





        }
    } catch (const std::exception& ex){
        QString errorMessage = QString::fromUtf8(ex.what());
        qWarning() << "Bilinmeyen Hata :" << errorMessage ;
    }


}

clsPacketOperation::~clsPacketOperation(){
    cout << "Destructor" << endl;

    if(handle != nullptr){
        //pcap_close(handle);
        handle = nullptr;
    }
    //packets.clear();
    //packetCount=0;

    //thread başlangıcını kodla
    MoveWorker* mw =new MoveWorker(filePath);
    QThread* wThread = new QThread;
    mw->moveToThread(wThread);

    QObject::connect(wThread,&QThread::started,mw,&MoveWorker::moveFile);
    QObject::connect(mw,&MoveWorker::moveFinished,wThread,&QThread::quit);
    QObject::connect(mw,&MoveWorker::moveFinished,mw,&MoveWorker::deleteLater);
    /*QObject::connect(mw,&MoveWorker::failedMove,[this](){
        qDebug() <<"Dosya tasinamadı , hata mevcut tekrar deneniyor ..";
        filesystem::path sPath(this->filePath);
        filesystem::path dPath = filesystem::path("C:\\Users\\remzi\\Desktop\\usedFile") / this->fileName;
        cout << dPath << endl;
        try{
            filesystem::rename(sPath,dPath);
            cout << "Dosya tasindi" << endl;
        }catch(const filesystem::filesystem_error& fError){
            cout << "Dosya tasinamadi , hata :" << fError.what() << endl;
        }
    });*/
    QObject::connect(mw,&MoveWorker::failedMove,mw,&MoveWorker::deleteLater);
    QObject::connect(wThread,&QThread::finished,wThread,&QThread::deleteLater);
    wThread->start();
    wThread->wait();

    QDateTime currTime = QDateTime::currentDateTime();
    qint64 sub = currTime.secsTo(objStartTime);

    qDebug() << this->fileName << " dosyasinin paket islem süresi : " << sub << " saniye ."  ;
    this->packetsInfo.clear();
    this->pCount = 0;

    this->clsSMap = nullptr;

}

void clsPacketOperation::packetCapture(int loopcount){


    if(controlOpen != true){
        qWarning() << "Geçerli dosya seçiniz !!";
    }else{
        qDebug() << "Paket yakalama basliyor !!" ;
        pcap_handler qHand = reinterpret_cast<pcap_handler>(&clsPacketOperation::processPacket);
        u_char* userData = reinterpret_cast<u_char*>(this);
        pcap_loop(this->handle,loopcount,qHand,userData);
        pcap_close(this->handle);
        this->clsSMap->setisLastPacket(true);

        qDebug() << "Toplam yakalanan paket sayisi : " << pCount;
    }





}




void clsPacketOperation::printCsvFile(){


    QString name = this->defaultCsvPath + this->fileName.left(fileName.lastIndexOf('.')) + ".csv";
    QFile baseCsv(name);
    if(!baseCsv.open(QIODevice::WriteOnly | QIODevice::Text)){
        qWarning() <<  "CSV acilmadi !!";
    }

    QTextStream bStream(&baseCsv);
    bStream << "Source IP;Destination IP;"
               "Source Port;Destination Port;"
               "Stream Index;Packets Count;"
               "Total Len;Source To Destination;"
               "Source To Destination Length;"
               "Destination To Source;Destination To Source Length;Protokol;"
               "Start Time;End Time;Sender; Recipient;\n";



    QString sipMessageName = this->defaultCsvPath +  this->fileName.left(fileName.lastIndexOf('.')) + "_Messages.csv";
    QFile messagesCsv(sipMessageName);
    if(!messagesCsv.open(QIODevice::WriteOnly | QIODevice::Text)){
        qWarning() <<  "CSV acilmadi !!";
    }

    QTextStream mStream(&messagesCsv);
    mStream << "Packet Number ; Protocol ;Protocol Message ; \n";


    for(auto it = sessionMap.cbegin();it!=sessionMap.cend();++it){

        const strSessıonInfo& value = it.value();

        QString strSender = value.smtpSender;
        QString strRece = value.smtpRecipient;
        strSender = strSender.replace(';',',');
        strRece = strRece.replace(';',',');
        //replace(strSender.begin(),strSender.end(),';',',');
        //replace(strRece.begin(),strRece.end(),';',',');
        bStream << value.sourceIP << ';' << value.destIP
                << ';' << value.sourcePort << ';' << value.destPort << ';' << value.streamIndex
                << ';' << value.packetCount << ';' << value.packetsLen << ';' << value.sourceTodest
                << ';' << value.sourceTodestLen << ';' << value.destToSource << ';' << value.destToSourceLen
                << ';' << value.protocol
                << ';' << value.startTime << ';' << value.endTime << ';' << strSender << ';' << strRece << "\n";

        for(int s=0;s<value.packetIndex.size();++s){
            if(value.messages[s] != " -- "){
                mStream << value.packetIndex[s] << ';' << value.protocol << ';' << value.messages[s] + "\n";


            }
        }
    }
    baseCsv.close();
    messagesCsv.close();

    //cout << name << " printCsvFile yazildi" << endl;




}


void clsPacketOperation::processPacket(void *user, const pcap_pkthdr *header, const u_char *pkt_data){


    clsPacketOperation* noStatic = reinterpret_cast<clsPacketOperation*>(user);

    QString tms = QString::number(header->ts.tv_sec) + "." + QString::number(header->ts.tv_usec);
    (noStatic->pCount)++;


    struct ipheader* ip_header = (struct ipheader*)(pkt_data + ETHERNET_HEADER_LENGTH);
    struct ethHeader* eth_header = (struct ethHeader*)pkt_data;

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->iph_sourceip), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->iph_destip), dest_ip, INET_ADDRSTRLEN);

    QString sMac ;
    for (int k = 0; k < 6; k++) {
        if (k > 0) {
            sMac += ":";
        }
        sMac += QString::number(eth_header->sourceMac[k], 16).rightJustified(2, '0').toUpper();

    }

    QString dMac;
    for (int l = 0; l < 6; l++) {
        if(l > 0){
            dMac += ":";
        }

        dMac += QString::number(eth_header->destMac[l], 16).rightJustified(2, '0').toUpper();
    }


    strPacketInfo pInfo;
    pInfo.sourceIP = source_ip;
    pInfo.destIP = dest_ip;
    pInfo.sourceMac = sMac;
    pInfo.destMac = dMac;
    pInfo.timestamp = tms;
    pInfo.packetLen = header->len ;


    noStatic->clsSMap->setPacketsInfo(pkt_data,header);



    if (ip_header->iph_protocol == IPPROTO_TCP || ip_header->iph_protocol == IPPROTO_UDP) {
        bool isTCP = (ip_header->iph_protocol == IPPROTO_TCP);
        const u_char* transport_header = pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader);
        int header_size = (isTCP ? (((struct tcphdr*)transport_header)->th_offx2 >> 4) * 4 : 8); //tcp size ve udp sabit size
        const u_char* payload = transport_header + header_size;
        int payload_length = header->caplen - (ETHERNET_HEADER_LENGTH + sizeof(struct ipheader) + header_size);

        uint16_t src_port = ntohs(isTCP ? ((struct tcphdr*)transport_header)->th_sport : ((struct udphdr*)transport_header)->uh_sport);
        uint16_t dest_port = ntohs(isTCP ? ((struct tcphdr*)transport_header)->th_dport : ((struct udphdr*)transport_header)->uh_dport);



        // SIP
        if (src_port == 5060 || dest_port == 5060) {

            QStringList rList = noStatic->parseSipMessage(reinterpret_cast<const char*>(payload), payload_length);
            //duruma göre bunrda from-to adresleri parseSipMessage içinde ayıklanabilir.
            pInfo.message = rList[0] ;
            pInfo.smtpSender = rList[1];
            pInfo.smtpRecipient = rList[2];

            // SMTP
        } else if (src_port == 25 || dest_port == 25) {
            auto mails = noStatic->parseSmtp(reinterpret_cast<const char*>(payload), payload_length);
            pInfo.smtpSender = mails.first;
            pInfo.smtpRecipient = mails.second;
            pInfo.message = " -- ";

            // POP3
        } else if (src_port == 110 || dest_port == 110) {
            pInfo.message = noStatic->parsePopPayload(reinterpret_cast<const char*>(payload), payload_length);
            pInfo.smtpSender = " -- ";
            pInfo.smtpRecipient = " -- ";

        } else {
            pInfo.message = " -- ";
            pInfo.smtpSender = " -- ";
            pInfo.smtpRecipient = " -- ";
        }




        pInfo.sourcePort = src_port;
        pInfo.destPort = dest_port;
        pInfo.protocol = isTCP ? "TCP" : "UDP";


        noStatic->createSessionMap(pInfo);
    }


}

void clsPacketOperation::createSessionMap(const strPacketInfo &p){


    QString key1 = p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.destIP + "-" + QString::number(p.destPort) + "-" + p.protocol;
    QString key2 = p.destIP + "-" + QString::number(p.destPort) + "-" + p.sourceIP + "-" + QString::number(p.sourcePort) + "-" + p.protocol;

    size_t directionKey = -1 ;
    strSessıonInfo* sI = nullptr;


    auto s1 = this->sessionMap.find(key1);
    if(s1 != this->sessionMap.end()){
        sI = &s1.value();
        directionKey = 0;
    }else{
        auto s2 = this->sessionMap.find(key2);
        if(s2 != this->sessionMap.end()){
            sI = &s2.value();
            directionKey = 1;
        }
    }

    if(sI == nullptr){
        int s = (p.protocol == "TCP") ? streamIndex++ : (p.protocol == "UDP") ? streamIndexUdp++ : pCount;

        strSessıonInfo newSession = {p.sourceIP,
                                  p.destIP,
                                  p.sourcePort,
                                  p.destPort,
                                  s,
                                  1,
                                  p.packetLen,
                                  1,
                                  p.packetLen,
                                  0,
                                  0,
                                  p.timestamp,
                                  p.timestamp,
                                  {pCount},
                                  {p.message},
                                  p.protocol,
                                  p.smtpSender,
                                  p.smtpRecipient};

        sessionMap[key1] = newSession;
    }else{
        sI->packetCount++;
        sI->packetsLen += p.packetLen;
        sI->endTime = p.timestamp;
        sI->packetIndex.push_back(this->pCount);
        sI->messages.push_back(p.message);



        if (p.smtpSender != " -- ") {
            sI->smtpSender = p.smtpSender;
        }
        if (p.smtpRecipient != " -- ") {
            sI->smtpRecipient = p.smtpRecipient;
        }

        // yön kontrolü
        if(directionKey == 0){
            sI->sourceTodest++;
            sI->sourceTodestLen += p.packetLen;
            this->clsSMap->updateSessionMap(key1,*sI);

        }else{
            sI->destToSource++;
            sI->destToSourceLen += p.packetLen;
            this->clsSMap->updateSessionMap(key2,*sI);

        }

    }


}






QString clsPacketOperation::parsePopPayload(const char *p, int pSize)
{

}

QStringList clsPacketOperation::parseSipMessage(const char *p, int pSize)
{

}

QPair<QString, QString> clsPacketOperation::parseSmtp(const char *p, int pSize)
{

}

