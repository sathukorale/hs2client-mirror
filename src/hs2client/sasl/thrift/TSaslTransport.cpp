/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <iostream>
#include <stdint.h>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>

#include <thrift/transport/TBufferTransports.h>
#include "hs2client/sasl/thrift/TSaslTransport.h"

const int32_t DEFAULT_MEM_BUF_SIZE = 32 * 1024;

namespace apache { namespace thrift { namespace transport {

  TSaslTransport::TSaslTransport(boost::shared_ptr<sasl::Tsasl> saslClient, boost::shared_ptr<TTransport> transport) : transport_(transport) {
	saslClient_ = saslClient;
    memBuf = new TMemoryBuffer();
    shouldWrap = false;
  }

  TSaslTransport::~TSaslTransport() {
    delete memBuf;
  }

  /**
   * Whether this transport is open.
   */
  bool TSaslTransport::isOpen() {
    return transport_->isOpen();
  }

  /**
   * Tests whether there is more data to read or if the remote side is
   * still open.
   */
  bool TSaslTransport::peek(){
    return (transport_->peek());
  }

  /* send message with SASL transport headers */
  void TSaslTransport::sendSaslMessage(NegotiationStatus status, uint8_t* payload, uint32_t length) {
    uint8_t messageHeader[STATUS_BYTES + PAYLOAD_LENGTH_BYTES];
    uint8_t dummy = 0;
    if (payload == NULL) {
      payload = &dummy;
    }
    messageHeader[0] = (uint8_t)status;
    encodeInt(length, messageHeader, STATUS_BYTES);
    transport_->write(messageHeader, HEADER_LENGTH);
    transport_->write(payload, length);
    transport_->flush();
  }

  void TSaslTransport::handleStartMessage() {
    uint32_t resLength = 0;
    uint8_t dummy = 0;
    uint8_t *initialResponse = &dummy;
    if (saslClient_->hasInitialResponse()) {
      initialResponse = saslClient_->evaluateChallenge(NULL, resLength);
    }

    sendSaslMessage(TSASL_START, (uint8_t*)saslClient_->getMechanismName().c_str(), 
        saslClient_->getMechanismName().length());
    sendSaslMessage(TSASL_OK, initialResponse, resLength);

    transport_->flush();
  }

  /**
   * Opens the transport for communications.
   *
   * @return bool Whether the transport was successfully opened
   * @throws TTransportException if opening failed
   */
  void TSaslTransport::open() 
  {
    NegotiationStatus status = TSASL_INVALID;
    uint32_t resLength;

    if (!transport_->isOpen())
      transport_->open();

    // initiate  SASL message
    handleStartMessage();

    // SASL connection handshake
    while (!saslClient_->isComplete()) 
    {
      do 
      {        
        uint8_t *message = receiveSaslMessage(status, resLength);
        if (status == TSASL_COMPLETE) {
          break; // handshake complete
        }
        if ( (status != TSASL_OK)) {
          throw TTransportException("Expected COMPLETE or OK, got " + status);
        }
        
        uint8_t* challenge = saslClient_->evaluateChallenge(message, resLength);
        sendSaslMessage(saslClient_->isComplete() ? TSASL_COMPLETE : TSASL_OK, challenge, resLength);
      } while (0);
    }

    // If the server isn't complete yet, we need to wait for its response. This will occur
    // with ANONYMOUS auth, for example, where we send an initial response and are 
    // immediately complete.
    if ((status == TSASL_INVALID) || (status == TSASL_OK)) {
      boost::shared_ptr<uint8_t> message(receiveSaslMessage(status, resLength));
      if (status != TSASL_COMPLETE) {
        throw TTransportException("Expected SASL COMPLETE, but got " + status);
      }
    }

    // TODO : need to set the shouldWrap based on QOP
    /*
    String qop = (String) sasl.getNegotiatedProperty(Sasl.QOP);
    if (qop != null && !qop.equalsIgnoreCase("auth"))
      shouldWrap = true;
    */
  }

  /**
   * Closes the transport.
   */
  void TSaslTransport::close() {
    transport_->close();
    saslClient_->dispose();
  }

  void TSaslTransport::shrinkBuffer() {
    // readEnd() returns the number of bytes already read, i.e. the number of 'junk' bytes
    // taking up space at the front of the memory buffer.
    uint32_t read_end = memBuf->readEnd();

    // If the size of the junk space at the beginning of the buffer is too large, and
    // there's no data left in the buffer to read (number of bytes read == number of bytes
    // written), then shrink the buffer back to the default. We don't want to do this on
    // every read that exhausts the buffer, since the layer above often reads in small
    // chunks, which is why we only resize if there's too much junk. The write and read
    // pointers will eventually catch up after every RPC, so we will always take this path
    // eventually once the buffer becomes sufficiently full.
    //
    // readEnd() may reset the write / read pointers (but only once if there's no
    // intervening read or write between calls), so needs to be called a second time to
    // get their current position.
    if (read_end > DEFAULT_MEM_BUF_SIZE && memBuf->writeEnd() == memBuf->readEnd()) {
      memBuf->resetBuffer(DEFAULT_MEM_BUF_SIZE);
    }
  }

    /**
   * Read a 4-byte word from the underlying transport and interpret it as an
   * integer.
   * 
   * @return The length prefix of the next SASL message to read.
   * @throws TTransportException
   *           Thrown if reading from the underlying transport fails.
   */
  uint32_t TSaslTransport::readLength() {
    uint8_t lenBuf[PAYLOAD_LENGTH_BYTES];

    transport_->readAll(lenBuf, PAYLOAD_LENGTH_BYTES);
    int32_t len = decodeInt(lenBuf, 0);
    if (len < 0) {
      throw TTransportException("Frame size has negative value");
    }
    return static_cast<uint32_t>(len);
  }


  /**
   * Attempt to read up to the specified number of bytes into the string.
   *
   * @param buf  Reference to the location to write the data
   * @param len  How many bytes to read
   * @return How many bytes were actually read
   * @throws TTransportException If an error occurs
   */
  uint32_t TSaslTransport::read(uint8_t* buf, uint32_t len) {
    uint32_t read_bytes = memBuf->read(buf, len);

    if (read_bytes > 0) {
      shrinkBuffer();
      return read_bytes;
    }

    // if there's not enough data in cache, read from underlying transport
    uint32_t dataLength = readLength();

    // Fast path
    if (len == dataLength && !shouldWrap) {
      transport_->readAll(buf, len);
      return len;
    }

    uint8_t* tmpBuf = new uint8_t[dataLength];
    transport_->readAll(tmpBuf, dataLength);
    if (shouldWrap) {
      tmpBuf = saslClient_->unwrap(tmpBuf, 0, dataLength);
    }

    // We will consume all the data, no need to put it in the memory buffer.
    if (len == dataLength) {
      memcpy(buf, tmpBuf, len);
      delete[] tmpBuf;
      return len;
    }

    memBuf->write(tmpBuf, dataLength);
    memBuf->flush();
    delete[] tmpBuf;

    uint32_t ret = memBuf->read(buf, len);
    shrinkBuffer();
    return ret;
  }

  /**
   * Write the given integer as 4 bytes to the underlying transport.
   * 
   * @param length
   *          The length prefix of the next SASL message to write.
   * @throws TTransportException
   *           Thrown if writing to the underlying transport fails.
   */
  void TSaslTransport::writeLength(uint32_t length) {
    uint8_t lenBuf[PAYLOAD_LENGTH_BYTES];

    encodeInt(length, lenBuf, 0);
    transport_->write(lenBuf, PAYLOAD_LENGTH_BYTES);
  }

    /**
   * Writes the string in its entirety to the buffer.
   *
   * Note: You must call flush() to ensure the data is actually written,
   * and available to be read back in the future.  Destroying a TTransport
   * object does not automatically flush pending data--if you destroy a
   * TTransport object with written but un-flushed data, that data may be
   * discarded.
   *
   * @param buf  The data to write out
   * @throws TTransportException if an error occurs
   */
  void TSaslTransport::write(const uint8_t* buf, uint32_t len) {
    const uint8_t* newBuf;

    if (shouldWrap) {
      newBuf = saslClient_->wrap(const_cast<uint8_t*>(buf), 0, len);
    } else {
      newBuf = buf;
    }
    writeLength(len);
    transport_->write(newBuf, len);
  }

  /**
   * Flushes any pending data to be written. Typically used with buffered
   * transport mechanisms.
   *
   * @throws TTransportException if an error occurs
   */
  void TSaslTransport::flush() {
    transport_->flush();
  }

    /**
   * Read a complete Thrift SASL message.
   * 
   * @return The SASL status and payload from this message.
   * @throws TTransportException
   *           Thrown if there is a failure reading from the underlying
   *           transport, or if a status code of BAD or ERROR is encountered.
   */
  uint8_t *TSaslTransport::receiveSaslMessage(NegotiationStatus &status , uint32_t& length) {
    uint8_t messageHeader[STATUS_BYTES + PAYLOAD_LENGTH_BYTES];

    // read header
    transport_->readAll(messageHeader, HEADER_LENGTH);

    // get payload length and status
    status= (NegotiationStatus)messageHeader[0];
    length = decodeInt(messageHeader, STATUS_BYTES);

    // get payload
    uint8_t* payload = new uint8_t[length];
    transport_->readAll(payload, length);

    if ((status < TSASL_START) || (status > TSASL_COMPLETE)) {
      throw TTransportException("invalid sasl status");
    } else if (status == TSASL_BAD || status == TSASL_ERROR) {
        throw TTransportException("sasl Peer indicated failure: ");
    }
    return payload;
  }

  /* store the big endian format int to given buffer */
  void TSaslTransport::encodeInt(uint32_t x, uint8_t* buf, uint32_t offset) {
    *(reinterpret_cast<uint32_t*>(buf + offset)) = htonl(x);
  }

  /* load the big endian format int to given buffer */
  uint32_t TSaslTransport::decodeInt (uint8_t* buf, uint32_t offset) {
    return ntohl(*(reinterpret_cast<uint32_t*>(buf + offset)));
  }
}
}
}