//
//  ndnrtc-library.cpp
//  ndnrtc
//
//  Copyright 2013 Regents of the University of California
//  For licensing details see the LICENSE file.
//
//  Author:  Peter Gusev
//

#include "ndnrtc-library.h"
#include "sender-channel.h"
#include "receiver-channel.h"

#include <memory>

#define CHECK_AND_SET_INT(paramSet, paramName, paramValue){ \
if ((int)paramValue >= 0) \
paramSet.setIntParam(paramName, paramValue); \
}

#define CHECK_AND_SET_STR(paramSet, paramName, paramValue){\
if (paramValue)\
paramSet.setStringParam(paramName, string(paramValue));\
}

using namespace ndnrtc;
using namespace std;

static shared_ptr<NdnSenderChannel> SenderChannel;
static map<string, shared_ptr<NdnReceiverChannel>> Producers;

//********************************************************************************
#pragma mark module loading
__attribute__((constructor))
static void initializer(int argc, char** argv, char** envp) {
    static int initialized = 0;
    if (!initialized) {
        initialized = 1;
        NdnLogger::initialize("ndnrtc.log", NdnLoggerDetailLevelAll);
        INFO("module loaded");
    }
}

__attribute__((destructor))
static void destructor(){
    INFO("module unloaded");
}

extern "C" NdnRtcLibrary* create_ndnrtc(void *libHandle)
{
    return new NdnRtcLibrary(libHandle);
}

extern "C" void destroy_ndnrtc( NdnRtcLibrary* object )
{
    delete object;
}

//********************************************************************************
#pragma mark - all static
static const char *DefaultLogFile = NULL;

//********************************************************************************
#pragma mark - construction/destruction
NdnRtcLibrary::NdnRtcLibrary(void *libHandle):
observer_(NULL),
libraryHandle_(libHandle),
libParams_(*ReceiverChannelParams::defaultParams())
{
    // setting up deafult params = receiver channel + sender channel params
    NdnParams *senderParams = SenderChannelParams::defaultParams();
    
    libParams_.addParams(*senderParams);
    
    delete senderParams;
}
//********************************************************************************
#pragma mark - public
void NdnRtcLibrary::configure(NdnLibParams &params)
{
    NdnLogger::initialize(params.logFile, params.loggingLevel);
    
    // capture settings
    CHECK_AND_SET_INT(libParams_, CameraCapturerParams::ParamNameDeviceId, params.captureDeviceId)
    CHECK_AND_SET_INT(libParams_, CameraCapturerParams::ParamNameWidth, params.captureWidth)
    CHECK_AND_SET_INT(libParams_, CameraCapturerParams::ParamNameHeight, params.captureHeight)
    CHECK_AND_SET_INT(libParams_, CameraCapturerParams::ParamNameFPS, params.captureFramerate)
    
    // render
    CHECK_AND_SET_INT(libParams_, NdnRendererParams::ParamNameWindowWidth, params.renderWidth)
    CHECK_AND_SET_INT(libParams_, NdnRendererParams::ParamNameWindowHeight, params.renderHeight)
    
    // codec
    CHECK_AND_SET_INT(libParams_, NdnVideoCoderParams::ParamNameFrameRate, params.codecFrameRate)
    CHECK_AND_SET_INT(libParams_, NdnVideoCoderParams::ParamNameStartBitRate, params.startBitrate)
    CHECK_AND_SET_INT(libParams_, NdnVideoCoderParams::ParamNameMaxBitRate, params.maxBitrate)
    CHECK_AND_SET_INT(libParams_, NdnVideoCoderParams::ParamNameWidth, params.encodeWidth)
    CHECK_AND_SET_INT(libParams_, NdnVideoCoderParams::ParamNameHeight, params.encodeHeight)
    
    // network
    CHECK_AND_SET_STR(libParams_, SenderChannelParams::ParamNameConnectHost, params.host)
    
    CHECK_AND_SET_INT(libParams_, SenderChannelParams::ParamNameConnectPort, params.portNum)
    
    // ndn producer
    CHECK_AND_SET_INT(libParams_, VideoSenderParams::ParamNameSegmentSize, params.segmentSize)
    CHECK_AND_SET_INT(libParams_, VideoSenderParams::ParamNameFrameFreshnessInterval, params.freshness)
    
    // ndn consumer
    CHECK_AND_SET_INT(libParams_, VideoReceiverParams::ParamNameProducerRate, params.playbackRate)
    CHECK_AND_SET_INT(libParams_, VideoReceiverParams::ParamNameInterestTimeout, params.interestTimeout)
    CHECK_AND_SET_INT(libParams_, VideoReceiverParams::ParamNameFrameBufferSize, params.bufferSize)
    CHECK_AND_SET_INT(libParams_, VideoReceiverParams::ParamNameFrameSlotSize, params.slotSize)
    
    notifyObserverWithState("init", "initialized with parameters: %s", libParams_.description().c_str());
}

NdnLibParams NdnRtcLibrary::getDefaultParams() const
{
    NdnLibParams defaultParams;
    
    memset(&defaultParams, -1, sizeof(defaultParams));
    
    defaultParams.loggingLevel = NdnLoggerDetailLevelDefault;
    defaultParams.logFile = DefaultLogFile;
    defaultParams.host = NULL;
    
    return defaultParams;
}

int NdnRtcLibrary::startConference(const char *username)
//int NdnRtcLibrary::startConference(NdnParams &params)
{
    if (username)
        libParams_.setStringParam(VideoSenderParams::ParamNameProducerId, username);
    
    shared_ptr<NdnSenderChannel> sc(new NdnSenderChannel(&libParams_));
    
    sc->setObserver(this);
    
    if (sc->init() < 0)
        return -1;
    
    if (sc->startTransmission() < 0)
        return -1;
    
    SenderChannel = sc;
    
    return notifyObserverWithState("transmitting",
                                   "started video translation under the user prefix: %s, video stream prefix: %s",
                                   static_cast<VideoSenderParams*>(&libParams_)->getUserPrefix().c_str(),
//                                   ((VideoSenderParams)libParams_).getUserPrefix().c_str(),
                                   static_cast<VideoSenderParams*>(&libParams_)->getStreamFramePrefix().c_str());
}

int NdnRtcLibrary::joinConference(const char *conferencePrefix)
{
    TRACE("join conference with prefix %s", conferencePrefix);
    
    if (Producers.find(string(conferencePrefix)) != Producers.end())
        return notifyObserverWithError("already joined conference");

    // setup params
    libParams_.setStringParam(VideoSenderParams::ParamNameProducerId, conferencePrefix);
    
    shared_ptr<NdnReceiverChannel> producer(new NdnReceiverChannel(&libParams_));
    
    producer->setObserver(this);
    
    if (producer->init() < 0)
        return -1;
    
    if (producer->startFetching() < 0)
        return -1;
    
    Producers[string(conferencePrefix)] = producer;
    
    return notifyObserverWithState("fetching",
                                   "fetching video from the prefix %s",
                                   static_cast<VideoSenderParams*>(&libParams_)->getStreamFramePrefix().c_str());
}

int NdnRtcLibrary::leaveConference(const char *conferencePrefix)
{
    TRACE("leaving conference with prefix: %s", conferencePrefix);
//    if (SenderChannel.get())
//    {
//        SenderChannel->stopTransmission();
//        SenderChannel.reset();
//    }
    
    if (Producers.find(string(conferencePrefix)) == Producers.end())
        return notifyObserverWithError("didn't find a conference to leave. did you join?");
    
    shared_ptr<NdnReceiverChannel> producer = Producers[string(conferencePrefix)];
    
    if (producer->stopFetching() < 0)
        notifyObserverWithError("can't leave the conference");
    
    Producers.erase(string(conferencePrefix));
    
    return notifyObserverWithState("leave", "left producer %s", conferencePrefix);
}

void NdnRtcLibrary::onErrorOccurred(const char *errorMessage)
{
    TRACE("error occurred");
    notifyObserverWithError(errorMessage);
}

//********************************************************************************
#pragma mark - private
int NdnRtcLibrary::notifyObserverWithError(const char *format, ...)
{
    va_list args;
    
    static char emsg[256];
    
    va_start(args, format);
    vsprintf(emsg, format, args);
    va_end(args);
    
    notifyObserver("error", emsg);
    
    return -1;
}
int NdnRtcLibrary::notifyObserverWithState(const char *stateName, const char *format, ...)
{
    va_list args;
    
    static char msg[256];
    
    va_start(args, format);
    vsprintf(msg, format, args);
    va_end(args);
    
    notifyObserver(stateName, msg);
    
    return 0;
}
void NdnRtcLibrary::notifyObserver(const char *state, const char *args)
{
    if (observer_)
        observer_->onStateChanged(state, args);
}