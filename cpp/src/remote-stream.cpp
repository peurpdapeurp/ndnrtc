//
// remote-stream.cpp
//
//  Created by Peter Gusev on 17 June 2016.
//  Copyright 2013-2016 Regents of the University of California
//

#include "remote-stream.hpp"
#include <memory>
#include <ndn-cpp/name.hpp>

#include "remote-stream-impl.hpp"
#include "remote-video-stream.hpp"
#include "remote-audio-stream.hpp"

using namespace ndnrtc;

//******************************************************************************
RemoteStream::RemoteStream(boost::asio::io_service& faceIo,
			const std::shared_ptr<ndn::Face>& face,
			const std::shared_ptr<ndn::KeyChain>& keyChain,
			const std::string& basePrefix,
			const std::string& streamName):
basePrefix_(basePrefix), streamName_(streamName)
{
}

RemoteStream::~RemoteStream(){
	pimpl_->setNeedsMeta(false);
}

bool
RemoteStream::isMetaFetched() const
{
	return pimpl_->isMetaFetched();
}

std::vector<std::string>
RemoteStream::getThreads() const
{
	return pimpl_->getThreads();
}

void
RemoteStream::setThread(const std::string& threadName)
{
	pimpl_->setThread(threadName);
}

std::string
RemoteStream::getThread() const
{
    return pimpl_->getThread();
}

void
RemoteStream::stop()
{
	pimpl_->stop();
}

void
RemoteStream::setInterestLifetime(unsigned int lifetime)
{
	pimpl_->setInterestLifetime(lifetime);
}

void
RemoteStream::setTargetBufferSize(unsigned int bufferSize)
{
	pimpl_->setTargetBufferSize(bufferSize);
}

statistics::StatisticsStorage
RemoteStream::getStatistics() const
{
	return pimpl_->getStatistics();
}

void
RemoteStream::setLogger(std::shared_ptr<ndnlog::new_api::Logger> logger)
{
	pimpl_->setLogger(logger);
}

bool
RemoteStream::isVerified() const
{
	return pimpl_->isVerified();
}

bool
RemoteStream::isRunning() const
{
    return pimpl_->isRunning();
}

void
RemoteStream::registerObserver(IRemoteStreamObserver* o)
{
    pimpl_->attach(o);
}

void
RemoteStream::unregisterObserver(IRemoteStreamObserver* o)
{
    pimpl_->detach(o);
}

std::shared_ptr<StorageEngine>
RemoteStream::getStorage() const
{
    throw std::runtime_error("Not implemented");
}

//******************************************************************************
RemoteAudioStream::RemoteAudioStream(boost::asio::io_service& faceIo,
			const std::shared_ptr<ndn::Face>& face,
			const std::shared_ptr<ndn::KeyChain>& keyChain,
			const std::string& basePrefix,
			const std::string& streamName,
			const int interestLifetime,
			const int jitterSizeMs):
RemoteStream(faceIo, face, keyChain, basePrefix, streamName)
{
	pimpl_ = std::make_shared<RemoteAudioStreamImpl>(faceIo, face, keyChain,
                                                       NameComponents::audioStreamPrefix(basePrefix).append(streamName).toUri());
	pimpl_->setInterestLifetime(interestLifetime);
	pimpl_->setTargetBufferSize(jitterSizeMs);
	pimpl_->fetchMeta();
}

void
RemoteAudioStream::start(const std::string& threadName)
{
	pimpl_->start(threadName);
}

//******************************************************************************
RemoteVideoStream::RemoteVideoStream(boost::asio::io_service& faceIo,
			const std::shared_ptr<ndn::Face>& face,
			const std::shared_ptr<ndn::KeyChain>& keyChain,
			const std::string& basePrefix,
			const std::string& streamName,
			const int interestLifetime,
			const int jitterSizeMs)
: RemoteStream(faceIo, face, keyChain, basePrefix, streamName)
{
	streamPrefix_ = NameComponents::videoStreamPrefix(basePrefix).append(streamName).toUri();
	pimpl_ = std::make_shared<RemoteVideoStreamImpl>(faceIo, face, keyChain, streamPrefix_);
	pimpl_->setInterestLifetime(interestLifetime);
	pimpl_->setTargetBufferSize(jitterSizeMs);
	pimpl_->fetchMeta();
}

void
RemoteVideoStream::start(const std::string& threadName, IExternalRenderer* renderer)
{
	std::dynamic_pointer_cast<RemoteVideoStreamImpl>(pimpl_)->start(threadName, renderer);
}
