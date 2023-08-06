import argparse
import requests
import json
from dateutil.parser import parse

def get_results(api_id, api_secret, domain, virtual_hosts):
    url = 'https://search.censys.io/api/v2/hosts/search'
    params = {
        'per_page': 100,
        'virtual_hosts': virtual_hosts,
        'q': domain
    }
    response = requests.get(
        url,
        params=params,
        auth=requests.auth.HTTPBasicAuth(api_id, api_secret),
        headers={'Accept': 'application/json'}
    )
    return response.json()


def print_service_info(service):
    print(f"\tPort: {service.get('port')}")
    print(f"\tService Name: {service.get('service_name')}")
    print(f"\tExtended Service Name: {service.get('extended_service_name')}")
    print(f"\tTransport Protocol: {service.get('transport_protocol')}")
    if 'certificate' in service:
        print(f"\tCertificate: {service.get('certificate')}")
    print("\t---")


def parse_results(results, ip_only):
    hits = results.get('result', {}).get('hits', [])
    ips = set()
    for hit in hits:
        ip = hit.get('ip')
        if ip not in ips:
            ips.add(ip)
            print('IP:', ip)
            if not ip_only:
                print('Name:', hit.get('name'))
                print('Country:', hit.get('location', {}).get('country'))
                print('City:', hit.get('location', {}).get('city'))
                print('Services:')
                for service in hit.get('services', []):
                    print_service_info(service)
                    if 'banner' in service:
                        print('\tBanner:', service['banner'])
                if 'operating_system' in hit:
                    os = hit['operating_system']
                    if 'cpe' in os:
                        print('OS CPE:', os['cpe'])
                if 'autonomous_system' in hit:
                    asys = hit['autonomous_system']
                    if 'asn' in asys:
                        print('AS Number:', asys['asn'])
                updated_at = parse(hit.get('last_updated_at'))
                print('Last Updated:', updated_at.strftime("%Y-%m-%d %H:%M:%S"))
                print('----------------------------------------')
                print('')


def export_to_html(results, filename, ip_only):
    hits = results.get('result', {}).get('hits', [])
    with open(filename, 'w') as f:
        f.write("<html>\n<body>\n")
        for hit in hits:
            f.write("<table border='1'>\n")
            f.write("<tr><td>IP:</td><td>{}</td></tr>\n".format(hit.get('ip')))
            if not ip_only:
                f.write("<tr><td>Name:</td><td>{}</td></tr>\n".format(hit.get('name')))
                f.write("<tr><td>Country:</td><td>{}</td></tr>\n".format(hit.get('location', {}).get('country')))
                f.write("<tr><td>City:</td><td>{}</td></tr>\n".format(hit.get('location', {}).get('city')))
                f.write("<tr><td>Services:</td><td>\n")
                for service in hit.get('services', []):
                    f.write(f"Port: {service.get('port')}, ")
                    f.write(f"Service Name: {service.get('service_name')}, ")
                    f.write(f"Extended Service Name: {service.get('extended_service_name')}, ")
                    f.write(f"Transport Protocol: {service.get('transport_protocol')}\n")
                    if 'banner' in service:
                        f.write(f"Banner: {service['banner']}\n")
                    f.write("<br>\n")
                f.write("</td></tr>\n")
                if 'operating_system' in hit:
                    os = hit['operating_system']
                    if 'cpe' in os:
                        f.write("<tr><td>OS CPE:</td><td>{}</td></tr>\n".format(os['cpe']))
                if 'autonomous_system' in hit:
                    asys = hit['autonomous_system']
                    if 'asn' in asys:
                        f.write("<tr><td>AS Number:</td><td>{}</td></tr>\n".format(asys['asn']))
                updated_at = parse(hit.get('last_updated_at'))
                f.write("<tr><td>Last Updated:</td><td>{}</td></tr>\n".format(updated_at.strftime("%Y-%m-%d %H:%M:%S")))
            f.write("</table>\n")
            f.write("<br>\n")
        f.write("</body>\n</html>")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fetch and parse results from Censys API.')
    parser.add_argument('--api_id', required=True, help='API ID for Censys')
    parser.add_argument('--api_secret', required=True, help='API Secret for Censys')
    parser.add_argument('--domain', required=True, help='Domain to search for')
    parser.add_argument('--virtual_hosts', default='INCLUDE', help='Whether to include or exclude virtual hosts. Default is INCLUDE.')
    parser.add_argument('--ip_only', default=False, action='store_true', help='Only display IPs')
    parser.add_argument('--export', default=None, help='File to export results as HTML')
    args = parser.parse_args()

    results = get_results(args.api_id, args.api_secret, args.domain, args.virtual_hosts)
    parse_results(results, args.ip_only)
    if args.export:
        export_to_html(results, args.export, args.ip_only)

