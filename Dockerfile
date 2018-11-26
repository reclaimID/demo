FROM ruby:alpine

WORKDIR /opt

COPY gnuid_svc.rb views Gemfile ./

RUN bundle install

EXPOSE 4567

CMD [ "ruby", "gnuid_svc.rb", "https://api.reclaim" ]

