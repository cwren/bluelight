#!/usr/bin/env python

# Copyright 2019 Chris Wren
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Heavily copied from cloudiot_mqtt_example.pp
# https://github.com/GoogleCloudPlatform/python-docs-samples/blob/master/iot/api-client/mqtt_example/cloudiot_mqtt_example.py

# [START iot_mqtt_includes]
import argparse
import datetime
import json
import os
import random
import ssl
import time

import jwt
import paho.mqtt.client as mqtt
# [END iot_mqtt_includes]

# [START bluelight_includes]
from gpiozero import LED 
from gpiozero import Button 
from time import sleep
from os import system
from signal import ITIMER_REAL
from signal import SIGALRM
from signal import SIGTERM
from signal import pause
from signal import setitimer
from signal import signal
# [END bluelight_includes]

EXPIRE_TIME = datetime.timedelta(minutes=60)

button = Button(16)
dome = LED(19)
network_light = LED(27)
status_light = LED(22)
args = None
client = None
device_id = 'foo'
last_toggle_time = time.time()

def toggle(): 
    global last_toggle_time
    now = time.time()
    if now - last_toggle_time < 2.0:
        return
    last_toggle_time = now

    if dome.value:
        state = 0
        dome.off()
    else:
        state = 1
        dome.on()

    payload = json.dumps({
            'registryId' : args.registry_id, 
            'deviceId' : device_id,
            'time' : now,
            'state' : state})
    mqtt_topic = '/devices/{}/events'.format(device_id)

    print('Button push message {}/{}'.format(mqtt_topic, payload))
    client.publish(mqtt_topic, payload, qos=1)

def termination_handler(signum, frame):
    network_light.off()
    status_light.off()
    quit()

def network_check_handler(signum, frame):
    network_check()

def network_check():
    hostname = "google.com"
    response = system("ping -q -c 1 8.8.8.8 > /dev/null" )
    if response == 0:
        network_light.on()
        return True
    else:
        network_light.off()
        return False

def create_jwt(project_id, private_key, algorithm):
    """Creates a JWT (https://jwt.io) to establish an MQTT connection.
        Args:
         project_id: The cloud project ID this device belongs to
         private_key_file: A path to a file containing either an RSA256 or
                 ES256 private key.
         algorithm: The encryption algorithm to use. Either 'RS256' or 'ES256'
        Returns:
            An MQTT generated from the given project_id and private key, which
            expires in 20 minutes. After 20 minutes, your client will be
            disconnected, and a new JWT will have to be generated.
        Raises:
            ValueError: If the private_key_file does not contain a known key.
        """

    token = {
            # The time that the token was issued at
            'iat': datetime.datetime.utcnow(),
            # The time the token expires.
            'exp': datetime.datetime.utcnow() + EXPIRE_TIME,
            # The audience field should always be set to the GCP project id.
            'aud': project_id
    }

    # Read the private key file.

    return jwt.encode(token, private_key, algorithm=algorithm)
# [END iot_mqtt_jwt]


# [START iot_mqtt_config]
def error_str(rc):
    """Convert a Paho error to a human readable string."""
    return '{}: {}'.format(rc, mqtt.error_string(rc))


def on_connect(unused_client, unused_userdata, unused_flags, rc):
    """Callback for when a device connects."""
    print('on_connect', mqtt.connack_string(rc))

    # This is the topic that the device will receive configuration updates on.
    mqtt_config_topic = '/devices/{}/config'.format(device_id)
    # Subscribe to the config topic.
    client.subscribe(mqtt_config_topic, qos=1)

    status_light.on()

def on_disconnect(unused_client, unused_userdata, rc):
    """Paho callback for when a device disconnects."""
    print('on_disconnect', error_str(rc))
    status_light.off()

def on_publish(unused_client, unused_userdata, unused_mid):
    """Paho callback when a message is sent to the broker."""
    print('on_publish')
    status_light.on()

def on_message(unused_client, unused_userdata, message):
    """Callback when the device receives a message on a subscription."""
    print('on_message')
    status_light.on()
    print('Received message \'{}\' on topic \'{}\' with Qos {}'.format(
            str(message.payload), message.topic, str(message.qos)))
    config = json.loads(message.payload)
    if config['state'] == 1:
        print('INTERPRETED STATUS AS ON')
        dome.on()
    else:
        print('INTERPRETED STATUS AS OFF')
        dome.off()

def set_token(client, project_id, private_key, algorithm):
    # With Google Cloud IoT Core, the username field is ignored, and the
    # password field is used to transmit a JWT to authorize the device.
    client.username_pw_set(
            username='unused',
            password=create_jwt(
                    project_id, private_key, algorithm))

def get_client(
        project_id, cloud_region, registry_id, device_id, private_key,
        algorithm, ca_certs, mqtt_bridge_hostname, mqtt_bridge_port):
    """Create our MQTT client. The client_id is a unique string that identifies
    this device. For Google Cloud IoT Core, it must be in the format below."""
    client = mqtt.Client(
            client_id=('projects/{}/locations/{}/registries/{}/devices/{}'
                       .format(
                               project_id,
                               cloud_region,
                               registry_id,
                               device_id)))

    set_token(client, project_id, private_key, algorithm)

    # Enable SSL/TLS support.
    client.tls_set(ca_certs=ca_certs, tls_version=ssl.PROTOCOL_TLSv1_2)

    # Register message callbacks. https://eclipse.org/paho/clients/python/docs/
    # describes additional callbacks that Paho supports. In this example, the
    # callbacks just print to standard out.
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    # Connect to the Google MQTT bridge.
    client.connect(mqtt_bridge_hostname, mqtt_bridge_port)

    return client
# [END iot_mqtt_config]


def parse_command_line_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=(
            'Bluelight IOT daemon.'))
    parser.add_argument(
            '--device_id',
            default='/etc/bluelight/device_id', 
            help='Name of file containing the Cloud IoT Core device id')
    parser.add_argument(
            '--project_id',
            default='bluelight-217214',
            help='GCP cloud project name')
    parser.add_argument(
            '--registry_id',
            default='example-registry',
            help='Cloud IoT Core registry id')
    parser.add_argument(
            '--private_key_file',
            default='/etc/bluelight/ec_private.pem',
            help='Path to private key file.')
    parser.add_argument(
            '--algorithm',
            choices=('RS256', 'ES256'),
            default='ES256',
            help='Which encryption algorithm to use to generate the JWT.')
    parser.add_argument(
            '--cloud_region',
            default='us-central1',
            help='GCP cloud region')
    parser.add_argument(
            '--ca_certs',
            default='/etc/bluelight/roots.pem',
            help=('CA root from https://pki.google.com/roots.pem'))
    parser.add_argument(
            '--mqtt_bridge_hostname',
            default='mqtt.googleapis.com',
            help='MQTT bridge hostname.')
    parser.add_argument(
            '--mqtt_bridge_port',
            choices=(8883, 443),
            default=8883,
            type=int,
            help='MQTT bridge port.')

    return parser.parse_args()


# [START iot_mqtt_run]
def main():
    global args
    global client
    global device_id

    button.when_pressed = toggle
    status_light.off()
    network_light.off()

    args = parse_command_line_args()

    with open(args.device_id, 'r') as f:
        device_id = f.readline().strip()
    print('I am {}'.format(device_id))

    with open(args.private_key_file, 'r') as f:
        private_key = f.read()
    print('key loaded')

    while not network_check():
        print("waiting for network")
        sleep(1)

    signal(SIGALRM, network_check_handler)
    signal(SIGTERM, termination_handler)
    setitimer(ITIMER_REAL, 10)

    client = get_client(
        args.project_id, args.cloud_region, args.registry_id,
        device_id, private_key, args.algorithm,
        args.ca_certs, args.mqtt_bridge_hostname, args.mqtt_bridge_port)
    client.loop_start()

    while True:
        time.sleep(EXPIRE_TIME.total_seconds() / 2) # ten minutes
        set_token(client, args.project_id, private_key, args.algorithm)

    client.loop_stop()
    print('Finished.')
# [END iot_mqtt_run]


if __name__ == '__main__':
    main()
