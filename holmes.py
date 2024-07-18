# Holmes - a lightweight framework to consistently inject frida over python.
import frida
import argparse
import time
import traceback


class Holmes:
    def on_message(self, message, data):
        print(f'main: {message}')

    def on_spawn_message(self, message, data):
        print(f'spawn: {message}')
        
    def __init__(self, args, bundle):
        self.bundle = bundle
        self.script_path = args.script
        self.config_path = args.config

    def spawn_removed(self, spawn):
        # An annoying issue in frida that I'm working on a PR to fix :)
        if spawn.identifier.startswith(self.bundle):
            print(f'spawn_removed - {spawn}')

    # Inject to subproccesses
    def spawn_added(self, spawn):
        try:
            if spawn.identifier.startswith(self.bundle) and len(
                    self.script_full_src) > 1 and self.frida_device is not None:
                print(f'spawn_added - {spawn}')
                session = self.frida_device.attach(spawn.pid)
                session_script_spawned = session.create_script(self.script_full_src)
                session_script_spawned.on('message', self.on_spawn_message)
                session_script_spawned.load()
                self.frida_device.resume(spawn.pid)
        except Exception as e:
            st = traceback.format_exc().replace('\n', '\\n')
            print(f'spawn_added exception - {e}, spawn - {spawn}, stacktrace - {st}')

    def observe(self):
        print('Waiting up to 5 seconds for the device to appear...')
        self.frida_device = frida.get_usb_device(5)


        self.frida_device.on('spawn-added', lambda spawn: self.spawn_added(spawn))
        self.frida_device.on('spawn-removed', lambda spawn: self.spawn_removed(spawn))

        print('Spawning PID')
        pid = self.frida_device.spawn(
            program=[
                self.bundle,
            ],
            #argv=['--debug', '--runtime=v8']
        )

        print('Attaching, creating session...')
        session = self.frida_device.attach(
            target=pid,
        )

        # No exception handling - this should fail loudly.
        with open(self.script_path) as script_file:
            self.script_full_src = f'{script_file.read()}'
            if self.config_path:
                with open(self.config_path) as config_file:
                    self.script_full_src = f'var config = {config_file.read()}\n\n{self.script_full_src}'
            session_script = session.create_script(self.script_full_src, runtime="v8")
            # session_script.enable_debugger()

        session_script.on('message', self.on_message)
        session_script.load()
        # Best simple entry point I've found (doesn't work for attachBaseContext=>native packer stuff)
        self.frida_device.resume(
            target=pid,
        )
        print('Script hooks successfully injected - sleeping for load')
        time.sleep(1)
        print('Done, ready for analysis.')
        # keep hooks working even after python process is closed
        # session_script.eternalize() 
        input()

if __name__ == '__main__':
    print(f'Starting main...')
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', default="com.twitter.android", help='Target bundle(s) to be analyzed on the device.')
    parser.add_argument('-s', '--script', default='lab.js', help='Path to Frida JS script to load')
    parser.add_argument('-c', '--config', default='config.json', help='A json file for configurations to pass to the frida script.')
    parsed_args = parser.parse_args()
    print('Parsed args, calling detective...')
    detective = Holmes(parsed_args, parsed_args.target)
    detective.observe()