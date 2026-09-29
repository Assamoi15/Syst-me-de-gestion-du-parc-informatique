import multiprocessing

bind = "127.0.0.1:9014"

workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

accesslog = "/var/log/parc/gunicorn_access.log"
errorlog = "/var/log/parc/gunicorn_error.log"
loglevel = "info"

proc_name = "parc_gunicorn"

daemon = False
pidfile = "/var/run/parc/gunicorn.pid"
user = "www-data"
group = "www-data"
