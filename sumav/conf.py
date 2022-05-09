'''
Configurations. You can change these values by using the environment variables.
'''
import os


def _split_env_var_to_list(var_name, default=''):
    items = [i.strip() for i in os.environ.get(var_name, default).split(',')
             if i.strip()]

    return items if len(items) > 0 else [default]


# ##### Common ##### #
intersection_ratio = float(os.environ.get('INTERSECTION_RATIO', '0.9'))
wait_for_reconnection = int(os.environ.get('WAIT_FOR_RECONNECTION', 60))
worker_concurrency = int(os.environ.get('WORKER_CONCURRENCY', (
    os.cpu_count() if os.cpu_count() <= 8 else os.cpu_count() / 2)))
vt_apikey = os.environ.get('VT_APIKEY', None)


# ##### Databases ##### #
# PostgreSQL #
psql_host = os.environ.get('PSQL_HOST', 'localhost')
psql_port = int(os.environ.get('PSQL_PORT', 5432))
psql_db = os.environ.get('PSQL_DB', 'sumav')
psql_user = os.environ.get('PSQL_USER', 'sumav')
psql_password = os.environ.get('PSQL_PASSWORD', 'sumav!@34')
psql_conf = {'host': psql_host, 'port': psql_port, 'user': psql_user,
             'password': psql_password, 'database': psql_db}


def get_conf():
    psql = {k: v for k, v in psql_conf.items() if not k.endswith('password')}
    return {'psql': psql}
