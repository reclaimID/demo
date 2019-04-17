FROM ruby:alpine

WORKDIR /opt

COPY target/Gemfile ./

RUN apk add -U curl make supervisor gcc && addgroup supervisor && adduser -G supervisor -s /bin/ash -D supervisor && bundle install && rm -rf /var/cache/apk/* /tmp/*
#RUN apk add -U curl supervisor && bundle install && rm -rf /var/cache/apk/* /tmp/*

COPY target/ ./

RUN chown -R supervisor:supervisor ./

EXPOSE 4567

#CMD [ "ruby", "demo.rb", "https://api.reclaim" ]
CMD [ "supervisord", "-c", "/opt/supervisord.conf" ]

