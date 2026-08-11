FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 8000
RUN sed -i 's/listen\s*80;/listen 8000;/' /etc/nginx/conf.d/default.conf
CMD ["nginx", "-g", "daemon off;"]
