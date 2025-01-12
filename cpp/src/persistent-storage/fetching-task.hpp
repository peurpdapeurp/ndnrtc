//
// fetching-task.hpp
//
//  Created by Peter Gusev on 27 May 2018.
//  Copyright 2013-2018 Regents of the University of California
//

#ifndef __fetching_task_hpp__
#define __fetching_task_hpp__

#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <ndn-cpp/name.hpp>
#include <ndn-cpp/face.hpp>

#include "simple-log.hpp"
#include "name-components.hpp"

namespace ndn {
    class Name;
    class Data;
    class Interest;
}

namespace ndnrtc {

    class SlotSegment;
    class BufferSlot;
    class IFetchMethod;
    class StorageEngine;
    class FetchingTask;

    typedef std::function<void(const std::shared_ptr<const FetchingTask>&, 
                                 std::string)> OnFetchingFailed;
    typedef std::function<void(const std::shared_ptr<const FetchingTask>&, 
                                 const std::shared_ptr<const BufferSlot>&)> OnFetchingComplete;
    typedef std::function<void(const std::shared_ptr<const FetchingTask>&, 
                                 const std::shared_ptr<const SlotSegment>&)> OnSegment;

    class FetchingTask {
        public: 
            typedef struct _Settings {
                int nRtx_;
                int interestLifeTimeMs_;
            } Settings;

            virtual ~FetchingTask(){}
    };

    class FrameFetchingTask : public FetchingTask,
                              public ndnlog::new_api::ILoggingObject,
                              public std::enable_shared_from_this<FrameFetchingTask> {
    public:
        enum State {
            Created = 0,
            Fetching,
            Canceled,
            Completed,
            Failed
        };
        /**
         * Creates new task for fetching frame.
         * @param name Full frame NDN name
         * @param nRtx Number of retries for interests that received timeouts
         * @param inFetchingComplete Callback which is called when frame was fully fetched
         * @param onFetchingFailed Called if frame couldn't be fetched
         * @param onFirstSegment Callback which is called when first segment (regardless of its' number) arrives
         * @param onZeroSegment Called when segmen #0 is fetched
         */
        FrameFetchingTask(const ndn::Name&, 
                          const std::shared_ptr<IFetchMethod>& fetchMethod,
                          OnFetchingComplete, 
                          OnFetchingFailed,
                          const FetchingTask::Settings& settings = {0, 1000},
                          OnSegment = OnSegment(), 
                          OnSegment = OnSegment());
        ~FrameFetchingTask();

        void start();
        void cancel();
        bool isFetching() const { return (state_ == Fetching); }
        State getState() const { return state_; }
        int getNacksNum() const { return nNacks_; }
        int getTimeoutsNum() const { return nTimeouts_; }
        ndn::Name getFrameName() const { return frameNameInfo_.getPrefix(prefix_filter::Sample); }
        const std::shared_ptr<const BufferSlot> getSlot() const { return slot_; }

    private:
        FetchingTask::Settings settings_;
        int taskProgress_, taskCompletion_;
        int nNacks_, nTimeouts_;
        State state_;

        std::shared_ptr<BufferSlot> slot_;
        NamespaceInfo frameNameInfo_;
        std::shared_ptr<IFetchMethod> fetchMethod_;
        std::shared_ptr<BufferSlot> frameSlot_;
        OnFetchingComplete onFetchingComplete_;
        OnFetchingFailed onFetchingFailed_;
        OnSegment onFirstSegment_, onZeroSegment_;

        std::vector<std::shared_ptr<const ndn::Interest>> 
        prepareBatch(ndn::Name n, bool noParity = false) const;

        void requestSegment(const std::shared_ptr<const ndn::Interest>& interest);
        void checkMissingSegments();
        void checkCompletion();
        std::shared_ptr<const ndn::Interest> makeInterest(const ndn::Name& name) const;
    };

    class IFetchMethod {
    public:
        virtual void express(const std::shared_ptr<const ndn::Interest>&,
                             ndn::OnData,
                             ndn::OnTimeout,
                             ndn::OnNetworkNack) = 0;
    };

    class FetchMethodLocal : public IFetchMethod {
    public:
        FetchMethodLocal(const std::shared_ptr<StorageEngine>& storage) : storage_(storage) {}
        ~FetchMethodLocal(){}

        void express(const std::shared_ptr<const ndn::Interest>&,
                             ndn::OnData,
                             ndn::OnTimeout,
                             ndn::OnNetworkNack) override;

    private:
        std::shared_ptr<StorageEngine> storage_;
    };

    class FetchMethodRemote : public IFetchMethod {
    public:

        void express(const std::shared_ptr<const ndn::Interest>&,
                             ndn::OnData,
                             ndn::OnTimeout,
                             ndn::OnNetworkNack) override {}
    };
}

#endif
