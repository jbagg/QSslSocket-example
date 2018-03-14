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
   File name    : link.cpp
   Created      : 12 March 2018
   Author(s)    : Jonathan Bagg
---------------------------------------------------------------------------------------------------
   Handles communication to the server
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#include <QSslKey>
#include <QSslCertificate>
#include "link.h"

Link::Link()
{
	connect(&server, &QSslSocket::readyRead, this, &Link::rx);
	connect(&server, &QSslSocket::disconnected, this, &Link::serverDisconnect);
	connect(&server, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(sslErrors(QList<QSslError>)));
	server.setPrivateKey("../../certificates/blue_local.key");
	server.setLocalCertificate("../../certificates/blue_local.pem");
	server.setPeerVerifyMode(QSslSocket::VerifyNone);
}

void Link::connectToServer()
{
	server.connectToHostEncrypted("127.0.0.1", 12345);
	if (server.waitForEncrypted(5000)) {
		server.write("Authentication Suceeded");
	}
	else {
		qDebug("Unable to connect to server");
		exit(0);
	}
}

void Link::sslErrors(const QList<QSslError> &errors)
{
	foreach (const QSslError &error, errors)
		qDebug() << error.errorString();
}

void Link::serverDisconnect(void)
{
	qDebug("Server disconnected");
	exit(0);
}

void Link::rx(void)
{
	qDebug() << server.readAll();
}
