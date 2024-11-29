use config::File;
use reqwest::{Client, Response, Url};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use chrono::Local;

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub check_ip_url: String,
    pub domains: Vec<Domain>,
}

#[derive(Debug, Deserialize)]
pub struct Domain {
    pub name: String,
    pub api_key: String,
    pub sub_domains: Vec<String>,
}

#[tokio::main]
async fn main() {
    let client = Client::new();

    let configuration: Configuration =
        config::Config::builder()
            .add_source(File::with_name("config.yaml"))
            .build()
            .unwrap_or_else(|_| panic!("Could not load config (config.yaml)"))
            .try_deserialize()
            .expect("Could not deserialize config");

    let url =
        Url::parse(&configuration.check_ip_url)
            .expect("CHECK IP URL not valid");

    let mut loops = 0;
    loop {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        println!("!!!! RUN {loops} - {now} !!!!");
        for domain in configuration.domains.iter() {
            println!("----------");
            println!("Checking ip URL: {}", url);

            let wan_ip = match get_wan_ip(&client, url.clone()).await {
                Ok(ip) => ip,
                Err(error) => {
                    eprintln!("failed to get WAN IP = {error}");
                    continue;
                }
            };

            println!("WAN IP = \"{wan_ip}\"");

            for host in domain.sub_domains.iter() {
                let endpoint = as_endpoint(host, &domain.name);

                println!("=> checking endpoint \"{endpoint}\"");

                let ips: Vec<IpAddr> = match dns_lookup::lookup_host(&endpoint) {
                    Ok(host) => host,
                    Err(error) => {
                        eprintln!("failed to lookup host = {error}");
                        continue;
                    }
                };

                println!("found IPs for {endpoint} = \"{ips:?}\"");

                if !ips.iter().any(|ip| is_same_ip_addr(ip, &wan_ip)) {
                    match update_domain(&client, &domain.name, host, &domain.api_key).await {
                        Ok(res) => println!("IP updated responded with status = {}", res.status()),
                        Err(error) => eprintln!("failed to update domain IP with error = {error}"),
                    };
                } else {
                    println!("{host}{} is up to date", domain.name);
                }
            }
        }
        loops += 1;
        tokio::time::sleep(Duration::new(60 * 5, 0)).await
    }
}

fn is_same_ip_addr(ip_addr: &IpAddr, wan_ip: &String) -> bool {
    match IpAddr::from_str(wan_ip) {
        Ok(ip) => {
            let is_same_ip = ip == *ip_addr;
            println!("{wan_ip} == {ip_addr}? {is_same_ip}");
            is_same_ip
        }
        Err(e) => {
            eprintln!("IP: {} is not a valid IP address: {}", wan_ip, e);
            false
        }
    }
}

async fn update_domain(client: &Client, domain: &str, host: &str, api_key: &String) -> reqwest::Result<Response> {
    let url_str =
        format!("https://dynamicdns.park-your-domain.com/update?host={host}&domain={domain}&password={api_key}");

    client.get(&url_str).send().await
}

async fn get_wan_ip(client: &Client, check_ip_url: Url) -> Result<String, reqwest::Error> {
    client.get(check_ip_url).send().await?.text().await.map(|text| text.trim().to_string())
}

pub fn as_endpoint(host: &str, domain: &str) -> String {
    let (host, separator) = match host {
        "*" | "@" => ("", ""),
        host => (host,".")
    };
    format!("{host}{separator}{domain}")
}