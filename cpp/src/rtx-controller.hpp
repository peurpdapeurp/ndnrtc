//
//  rtx-controller.hpp
//  ndnrtc
//
//  Copyright 2017 Regents of the University of California
//  For licensing details see the LICENSE file.
//
//  Author:  Peter Gusev
//

#ifndef __rtx_controller_h__
#define __rtx_controller_h__

#include <ndn-cpp/name.hpp>
#include "frame-buffer.hpp"
#include "statistics.hpp"

namespace ndnrtc
{
class IPlaybackQueue;
class IRtxObserver;
class DrdEstimator;

class RetransmissionController : public NdnRtcComponent,
                                 public IBufferObserver,
                                 public statistics::StatObject
{
  public:
    RetransmissionController(std::shared_ptr<statistics::StatisticsStorage> storage,
                             std::shared_ptr<IPlaybackQueue> playbackQueue,
                             const std::shared_ptr<DrdEstimator> &drdEstimator);

    void attach(IRtxObserver *observer);
    void detach(IRtxObserver *observer);

    void setEnabled(bool enable);
    bool isEnabled() { return enabled_; }

  private:
    typedef struct _ActiveSlotListEntry
    {
        std::shared_ptr<BufferSlot> slot_;
        int64_t deadlineTimestamp_;
    } ActiveSlotListEntry;

    std::vector<IRtxObserver *> observers_;
    std::map<ndn::Name, ActiveSlotListEntry> activeSlots_;
    std::shared_ptr<IPlaybackQueue> playbackQueue_;
    std::shared_ptr<DrdEstimator> drdEstimator_;
    bool enabled_;

    void checkRetransmissions();

    // IBuffer observer
    void onNewRequest(const std::shared_ptr<BufferSlot> &);
    void onNewData(const BufferReceipt &receipt);
    void onReset();
};

class IRtxObserver
{
  public:
    virtual void onRetransmissionRequired(const std::vector<std::shared_ptr<const ndn::Interest>> &) = 0;
};
}

#endif
