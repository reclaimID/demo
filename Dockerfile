FROM ruby:alpine

WORKDIR /opt

COPY gnuid_svc.rb Gemfile ./

COPY views ./views

RUN apk add -U curl && bundle install && rm -rf /var/cache/apk/* /tmp/*

EXPOSE 4567

CMD [ "ruby", "gnuid_svc.rb", "https://api.reclaim" ]

