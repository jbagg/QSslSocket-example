/**************************************************************************************************
---------------------------------------------------------------------------------------------------
	Copyright (c) 2018, Jonathan Bagg
	All rights reserved.

	 Redistribution and use in source and binary forms, with or without modification, are permitted
	 provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice, this list of
	  conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice, this list of
	  conditions and the following disclaimer in the documentation and/or other materials provided
	  with the distribution.
	* Neither the name of Jonathan Bagg nor the names of its contributors may be used to
	  endorse or promote products derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------------------------------
   Project name : QSslSocket Example
   File name    : sslserver.cpp
   Created      : 12 March 2018
   Author(s)    : Jonathan Bagg
---------------------------------------------------------------------------------------------------
   Simple secure TCP socket server
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#include <QSslSocket>
#include <QFile>
#include "sslserver.h"

SslServer::SslServer(QObject *parent) : QTcpServer(parent)
{
	QFile keyFile("../../certificates/red_local.key");
	keyFile.open(QIODevice::ReadOnly);
	key = QSslKey(keyFile.readAll(), QSsl::Rsa);
	keyFile.close();

	QFile certFile("../../certificates/red_local.pem");
	certFile.open(QIODevice::ReadOnly);
	cert = QSslCertificate(certFile.readAll());
	certFile.close();

	if (!listen(QHostAddress("127.0.0.1"), 12345)) { // FQDN in red_local.pem is set to 127.0.0.1.  If you change this, it will not authenticate.
		qCritical() << "Unable to start the TCP server";
		exit(0);
	}
	connect(this, &SslServer::newConnection, this, &SslServer::link);
}

void SslServer::incomingConnection(qintptr socketDescriptor)
{
	QSslSocket *sslSocket = new QSslSocket(this);

	connect(sslSocket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(sslErrors(QList<QSslError>)));
	sslSocket->setSocketDescriptor(socketDescriptor);
	sslSocket->setPrivateKey(key);
	sslSocket->setLocalCertificate(cert);
	sslSocket->addCaCertificates("../../certificates/blue_ca.pem");
	sslSocket->setPeerVerifyMode(QSslSocket::VerifyPeer);
	sslSocket->startServerEncryption();

	addPendingConnection(sslSocket);
}

void SslServer::sslErrors(const QList<QSslError> &errors)
{
	foreach (const QSslError &error, errors)
		qDebug() << error.errorString();
}

void SslServer::link()
{
	QTcpSocket *clientSocket;

	clientSocket = nextPendingConnection();
	connect(clientSocket, &QTcpSocket::readyRead, this, &SslServer::rx);
	connect(clientSocket, &QTcpSocket::disconnected, this, &SslServer::disconnected);
}

void SslServer::rx()
{
	QTcpSocket* clientSocket = qobject_cast<QTcpSocket*>(sender());
	qDebug() << clientSocket->readAll();
	clientSocket->write("Server says Hello");
}

void SslServer::disconnected()
{
	qDebug("Client Disconnected");
}
