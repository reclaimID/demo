FROM ruby:alpine

WORKDIR /opt

COPY target/ ./

RUN apk add -U curl && bundle install && rm -rf /var/cache/apk/* /tmp/*

EXPOSE 4567

CMD [ "ruby", "demo.rb", "https://api.reclaim" ]

