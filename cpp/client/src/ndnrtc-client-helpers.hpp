//
// ndnrtc-client-helpers.hpp
//
//  Created by Peter Gusev on 03 March 2016.
//  Modified by Edward Lu on 22 June 2019.
//  Copyright 2013-2016 Regents of the University of California
//

#ifndef
#define NDNRTC_CLIENT_HELPERS_HPP

using namespace std;
using namespace ndnrtc;
using namespace ndnrtc::helpers;
using namespace ndn;

struct Args
{
    unsigned int runTimeSec_, samplePeriod_;
    std::string configFile_, identity_, instance_, policy_;
    ndnlog::NdnLoggerDetailLevel logLevel_;
};

int run(const struct Args &);

void registerPrefix(boost::shared_ptr<Face> &, const KeyChainManager &);

void publishCertificate(boost::shared_ptr<Face> &, KeyChainManager &);

#endif // NDNRTC_CLIENT_HELPERS_HPP
