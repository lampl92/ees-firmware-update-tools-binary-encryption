#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <qrsaencryption.h>
#include <QDataStream>
#include<cstring>
#include <QByteArray>
int keygen();
int help();
int encrypt(int argc, char *argv[]);
int decrypt(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int ret = 0;

    qDebug() << "KeyGen version 1.0.0";
    if(argc > 1) {
        if (strcmp(argv[1], "keygen") == 0) {
            ret = keygen();
        }
        if (strcmp(argv[1], "enc") == 0) {
            ret = encrypt(argc - 1, &argv[1]);
        }
        if (strcmp(argv[1], "dec") == 0) {
            ret = decrypt(argc - 1, &argv[1]);
        }
        if (strcmp(argv[1], "help") == 0) {
            ret = help();
        }
    } else {
        ret = help();
    }

    return ret;
}

int keygen()
{
    QByteArray pub, priv;

    QRSAEncryption e(QRSAEncryption::Rsa::RSA_64);

    e.generatePairKey(pub, priv);

    QFile filepriv("priv.key");
    if(filepriv.exists()) {
        qDebug() << "priv.key already exist";
        return 1;
    }

    QFile filepub("pub.key");
    if(filepub.exists()) {
        qDebug() << "pub.key already exist";
        return 1;
    }

    if(!filepriv.open(QIODevice::WriteOnly)) {
        qDebug() << "dont have permission open priv.key";
        return 1;
    }
    filepriv.write(pub);
    filepriv.close();

    if(!filepub.open(QIODevice::WriteOnly)) {
        qDebug() << "dont have permission open pub.key";
        return 1;
    }

    filepub.write(priv);
    filepub.close();

    qDebug() << "priv : " << priv.toHex(' ');
    qDebug() << "public : " << pub.toHex(' ');
    return 0;
}

int encrypt(int argc, char *argv[])
{
    int ret = 0;
    if (argc < 2) {
       ret = help();
    } else {
        QFile inputFile(argv[1]);
        QFile outputFile(argv[2]);
        QRSAEncryption e(QRSAEncryption::Rsa::RSA_64);

        QFile pubkeyfile("pub.key");
        if(!pubkeyfile.exists()) {
            qDebug() << "pub.key not exist already exist";
            return 1;
        }

        if (outputFile.exists()) {
            qDebug() << "output file already exist";
            return 1;
        }

        QByteArray pubkeyBytes;
        pubkeyfile.open(QIODevice::ReadOnly);

        pubkeyBytes = pubkeyfile.readAll();
        qDebug() << "pubkey : " << pubkeyBytes.toHex(' ');
        pubkeyfile.close();

        if (!inputFile.exists()) {
            qDebug() << "input file not exist";
            return 1;
        }

        if(!inputFile.open(QFile::ReadOnly)) {
            qDebug() << "input file dont have permission";
            return 1;
        }

        if(inputFile.size() == 0) {
            qDebug() << "input file size is zero";
            return 1;
        }

        QByteArray inputdata;
        inputdata = inputFile.readAll();

        auto encodeData = e.encode(inputdata, pubkeyBytes, QRSAEncryption::BlockSize::OneByte);

        inputFile.close();

        if(!outputFile.open(QFile::WriteOnly)) {
            qDebug() << "input file dont have permission";
            return 1;
        }

        outputFile.write(encodeData);
        outputFile.close();
        qDebug() << "Encrypt file " << argv[1] << " to " << argv[2];

    }
    return ret;
}

int decrypt(int argc, char *argv[])
{
    int ret = 0;
    if (argc < 2) {
       ret = help();
    } else {
        QFile inputFile(argv[1]);
        QFile outputFile(argv[2]);
        QRSAEncryption e(QRSAEncryption::Rsa::RSA_64);
        QFile privKeyFile("priv.key");
        if(!privKeyFile.exists()) {
            qDebug() << "priv.key not exist already exist";
            return 1;
        }

        if (outputFile.exists()) {
            qDebug() << "output file already exist";
            return 1;
        }

        QByteArray privBytes;
        privKeyFile.open(QIODevice::ReadOnly);

        privBytes = privKeyFile.readAll();

        qDebug() << "Private key : " << privBytes.toHex(' ');
        privKeyFile.close();

        if (!inputFile.exists()) {
            qDebug() << "input file not exist";
            return 1;
        }

        if(!inputFile.open(QFile::ReadOnly)) {
            qDebug() << "input file dont have permission";
            return 1;
        }

        if(inputFile.size() == 0) {
            qDebug() << "input file size is zero";
            return 1;
        }

        QByteArray inputdata = inputFile.readAll();

        auto decodeData = e.decode(inputdata, privBytes, QRSAEncryption::BlockSize::OneByte);

        inputFile.close();

        if(!outputFile.open(QFile::WriteOnly)) {
            qDebug() << "input file dont have permission";
            return 1;
        }

        outputFile.write(decodeData);
        outputFile.close();
        qDebug() << "Decrypt file " << argv[1] << " to " << argv[2];

    }
    return ret;
}

int help()
{
    qDebug() << "Command help:";
    qDebug() << "\t keygen : generate 2 file, pub.key for encrypt and priv.key for decrypt";
    qDebug() << "\t enc <input filename> <output filename> : encrypt binary file with pub.key";
    qDebug() << "\t dec <input filename> <output filename> : decrypt binary file with priv.key";
    return 1;
}
