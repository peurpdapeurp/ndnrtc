//
// remote-stream.h
//
//  Created by Peter Gusev on 07 March 2016.
//  Copyright 2013-2016 Regents of the University of California
//

#ifndef __client_stream_h__
#define __client_stream_h__

#include <stdlib.h>
#include <ndnrtc/stream.hpp>
#include <ndnrtc/remote-stream.hpp>
#include <ndnrtc/local-stream.hpp>

#include "renderer.hpp"
#include "video-source.hpp"

class Stream
{
  public:
    Stream(std::shared_ptr<ndnrtc::IStream> stream) : stream_(stream) {}
    virtual ~Stream() {}

    std::shared_ptr<const ndnrtc::IStream> getStream() const { return stream_; }
    std::shared_ptr<ndnrtc::IStream> getStream() { return stream_; }

  protected:
    std::shared_ptr<ndnrtc::IStream> stream_;
};

class RemoteStream : public Stream
{
  public:
    // RemoteStream(RemoteStream&& rs){}
    RemoteStream(std::shared_ptr<ndnrtc::RemoteStream> stream, std::shared_ptr<RendererInternal> &&renderer) : Stream(stream), renderer_(boost::move(renderer)) {}
    ~RemoteStream() {}

    RendererInternal *getRenderer() const { return renderer_.get(); }

  private:
    std::shared_ptr<RendererInternal> renderer_;
};

class LocalStream : public Stream
{
  public:
    LocalStream(const LocalStream &ls) : Stream(ls),
                                         vsource_(boost::move(ls.getVideoSource())) {}
    LocalStream(std::shared_ptr<ndnrtc::IStream> stream,
                std::shared_ptr<VideoSource> &vsource) : Stream(stream), vsource_(boost::move(vsource)) {}
    ~LocalStream() {}

    std::shared_ptr<VideoSource> getVideoSource() const { return vsource_; }
    void stopSource()
    {
        if (vsource_.get())
            vsource_->stop();
    }

  private:
    std::shared_ptr<VideoSource> vsource_;
};

#endif
