//
// meta-fetcher.cpp
//
//  Created by Peter Gusev on 17 June 2016.
//  Copyright 2013-2016 Regents of the University of California
//

#include "meta-fetcher.hpp"
#include <boost/thread.hpp>
#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/key-chain.hpp>

#include "name-components.hpp"

using namespace ndn;
using namespace ndnrtc;

void MetaFetcher::fetch(std::shared_ptr<ndn::Face> f, std::shared_ptr<ndn::KeyChain> kc,
                        const ndn::Name &prefix, const OnMeta &onMeta, const OnError &onError)
{
    LogTraceC << "fetching meta for " << prefix << std::endl;

    Interest i(prefix, 3000);

    isPending_ = true;
    std::shared_ptr<MetaFetcher> me = std::dynamic_pointer_cast<MetaFetcher>(shared_from_this());
    // uses ndnrtc implementation of SegmentFetcher, NOT the one from NDN-CPP
    SegmentFetcher::fetch(*f, i, kc.get(),
                          [onMeta, me, f, kc, this](const Blob &content, const std::vector<ValidationErrorInfo> &info) {
                              isPending_ = false;
                              ImmutableHeaderPacket<DataSegmentHeader> packet(content);
                              NetworkData nd(packet.getPayload().size(), packet.getPayload().data());
                              onMeta(nd, info);
                          },
                          [onError, me, f, kc, this](SegmentFetcher::ErrorCode code, const std::string &msg) {
                              isPending_ = false;
                              onError(msg);
                          });
}
