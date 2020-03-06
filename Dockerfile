FROM httpd:alpine

COPY ./web/httpd.conf ./conf/httpd.conf
COPY ./web/htdocs/ ./htdocs
COPY ./version.txt ./htdocs
COPY ./build/bleenky.bin ./htdocs

EXPOSE 5000
