FROM ruby:alpine

WORKDIR /opt

COPY target/Gemfile ./

RUN apk add -U curl && bundle install && rm -rf /var/cache/apk/* /tmp/*

COPY target/ ./

EXPOSE 4567

CMD [ "ruby", "demo.rb", "https://api.reclaim" ]

