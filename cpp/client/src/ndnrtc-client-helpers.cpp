//
// ndnrtc-client-helpers.cpp
//
//  Created by Peter Gusev on 03 March 2016.
//  Copyright 2013-2016 Regents of the University of California
//

#include <iostream>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread.hpp>
#include <ndn-cpp/threadsafe-face.hpp>
#include <ndn-cpp/security/key-chain.hpp>
#include <ndn-cpp/security/certificate/identity-certificate.hpp>
#include <ndn-cpp/util/memory-content-cache.hpp>

#ifndef __ANDROID__
#include <execinfo.h>
#endif

#include "config.hpp"
#include "client.hpp"
#include <ndnrtc/helpers/key-chain-manager.hpp>
#include <ndnrtc/helpers/face-processor.hpp>

using namespace std;
using namespace ndnrtc;
using namespace ndnrtc::helpers;
using namespace ndn;

//******************************************************************************
int run(const struct Args &args)
{
    int err = 0;

    ndnlog::new_api::Logger::initAsyncLogging();
    ndnlog::new_api::Logger::getLogger("").setLogLevel(args.logLevel_);

    LogInfo("") << "Starting headless client... Params:\n"
                << "\tlog level: " << args.logLevel_
                << "\n\trun time: " << args.runTimeSec_
                << "\n\tconfig file: " << args.configFile_
                << "\n\tsigning identity: " << args.identity_
                << "\n\tpolicy file: " << args.policy_
                << "\n\tstatistics sampling: " << args.samplePeriod_
                << "\n\tinstance name: " << args.instance_
                << std::endl;

    boost::asio::io_service io;
    boost::shared_ptr<boost::asio::io_service::work> work(boost::make_shared<boost::asio::io_service::work>(io));
    boost::thread t([&io, &err]() {
        try
        {
            io.run();
        }
        catch (std::exception &e)
        {
            LogError("") << "Client caught exception while running: " << e.what() << std::endl;
            err = 1;
        }
    });

    boost::asio::io_service rendererIo;
    boost::shared_ptr<boost::asio::io_service::work> rendererWork(boost::make_shared<boost::asio::io_service::work>(rendererIo));
    boost::thread rendererThread([&rendererIo](){ 
      try {
        rendererIo.run(); 
      }
      catch (std::exception &e)
      {
        LogError("") << "caught exception on rednering thread: " << e.what() << std::endl;
      }
    });

    boost::shared_ptr<Face> face(boost::make_shared<ThreadsafeFace>(io));
    KeyChainManager keyChainManager(face, boost::make_shared<ndn::KeyChain>(),
                                    args.identity_, args.instance_,
                                    args.policy_, args.runTimeSec_,
                                    ndnlog::new_api::Logger::getLoggerPtr(""));
    ClientParams params;

    LogInfo("") << "Run time is set to " << args.runTimeSec_ << " seconds, loading "
                                                                "params from "
                << args.configFile_ << "..." << std::endl;

    if (loadParamsFromFile(args.configFile_, params, keyChainManager.instancePrefix()) == EXIT_FAILURE)
    {
        LogError("") << "error loading params from " << args.configFile_ << std::endl;
        return 1;
    }

    LogInfo("") << "Parameters loaded" << std::endl;
    LogDebug("") << params << std::endl;

    Client client(io, rendererIo, face, keyChainManager.instanceKeyChain());

    try
    {
        if (params.isProducing())
        {
            keyChainManager.publishCertificates();
            registerPrefix(face, keyChainManager);
        }

        client.run(args.runTimeSec_, args.samplePeriod_, params, args.instance_);

        face->shutdown();
        face.reset();
        work.reset();
        t.join();
        io.stop();
    }
    catch (std::exception &e)
    {
        LogError("") << "Client caught exception: " << e.what() << std::endl;
        err = 1;
    }

    LogInfo("") << "Client run completed" << std::endl;

    rendererWork.reset();
    rendererThread.join();
    rendererIo.stop();

    // NOTE: this is temporary sleep. should fix simple-log for flushing all log records before release
    sleep(1);
    ndnlog::new_api::Logger::releaseAsyncLogging();
    return err;
}

void registerPrefix(boost::shared_ptr<Face> &face, const KeyChainManager &keyChainManager)
{
    boost::mutex m;
    boost::unique_lock<boost::mutex> lock(m);
    boost::condition_variable isDone;
    boost::atomic<bool> completed(false);
    bool registered = false;

    face->registerPrefix(Name(keyChainManager.instancePrefix()),
                         [](const boost::shared_ptr<const Name> &prefix,
                            const boost::shared_ptr<const Interest> &interest,
                            Face &face, uint64_t, const boost::shared_ptr<const InterestFilter> &) {
                             LogTrace("") << "Unexpected incoming interest " << interest->getName() << std::endl;
                         },
                         [&completed, &isDone](const boost::shared_ptr<const Name> &prefix) {
                             LogError("") << "Prefix registration failure (" << prefix << ")" << std::endl;
                             completed = true;
                             isDone.notify_one();
                         },
                         [&completed, &registered, &isDone](const boost::shared_ptr<const Name> &p, uint64_t) {
                             LogInfo("") << "Successfully registered prefix " << *p << std::endl;
                             registered = true;
                             completed = true;
                             isDone.notify_one();
                         });
    isDone.wait(lock, [&completed]() { return completed.load(); });

    if (!registered)
        throw std::runtime_error("Prefix registration failed");
}

void publishCertificate(boost::shared_ptr<Face> &face, KeyChainManager &keyManager)
{
    static MemoryContentCache cache(face.get());
    Name filter;

    if (keyManager.defaultKeyChain()->getIsSecurityV1())
        filter = keyManager.instanceCertificate()->getName().getPrefix(keyManager.instanceCertificate()->getName().size() - 1);
    else
        filter = keyManager.instanceCertificate()->getName().getPrefix(keyManager.instanceCertificate()->getName().size() - 2);

    LogTrace("") << "Setting interest filter for instance certificate: " << filter << std::endl;

    cache.setInterestFilter(filter);
    cache.add(*(keyManager.instanceCertificate().get()));
}
