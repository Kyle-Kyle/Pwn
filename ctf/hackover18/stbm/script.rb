#!/usr/bin/env ruby
#puts(<<-'MOTD')
# .----------------.  .----------------.  .----------------.  .----------------.
#| .--------------. || .--------------. || .--------------. || .--------------. |
#| |    _______   | || |  _________   | || |   ______     | || | ____    ____ | |
#| |   /  ___  |  | || | |  _   _  |  | || |  |_   _ \    | || ||_   \  /   _|| |
#| |  |  (__ \_|  | || | |_/ | | \_|  | || |    | |_) |   | || |  |   \/   |  | |
#| |   '.___`-.   | || |     | |      | || |    |  __'.   | || |  | |\  /| |  | |
#| |  |`\____) |  | || |    _| |_     | || |   _| |__) |  | || | _| |_\/_| |_ | |
#| |  |_______.'  | || |   |_____|    | || |  |_______/   | || ||_____||_____|| |
#| |              | || |              | || |              | || |              | |
#| '--------------' || '--------------' || '--------------' || '--------------' |
# '----------------'  '----------------'  '----------------'  '----------------'
#
#Welcome to ze Schnelle Tunnelbohrmaschine Mark III Admin Interfetz.
#
#  © Copyright by Kryssen-Trupp 2018
#
#Type help or see handbook for more information.
#MOTD

# use digest and base64 for MD5 checksum compare on firmware update
require "digest"
require "base64"

# use CANT Bus implementation to talk to attached hardware on drilling
# machine.
#require_relative "cant_bus"

# simple helper methods for creating a better prompt experience
def log(text, modes = [:suffix])
  puts if modes.include? :prefix
  print text
  puts if modes.include? :suffix
end

def prompt
  log "> ", [:prefix]
end

### Modules
#
# Modules allow us to seperate different concern of the STBM III in
# different smaller parts, which are easier to reason about.
#
module CommonCommands
  def self.extended(extendee)
    extendee.module_exec do
      module_function
      def quit
        log "Bye! Disconnecting now…", [:prefix, :suffix]
        exit true
      end

      def help(parameter = nil)
        text = if parameter
          "Please take a look at the manual for more information about: #{parameter}"
        else
          "Available commands: #{self.methods(false).sort.join(", ")}"
        end

        log text, [:prefix, :suffix]
      end

      def switch_module(module_name)
        if VALID_MODULES.include?(module_name)
          ROOT_MODULE.local_variable_set :context, module_name
        else
          log "Invalid Module: #{module_name}"

          CommonCommands.available_modules
        end
      end

      def available_modules
        log "Available modules: #{VALID_MODULES.sort.join(", ")}", [:prefix, :suffix]
      end
    end
  end

  extend self
end

module SystemCommands
  extend CommonCommands
  module_function

  def version
    log "1.0.1-Final"
  end

  # Operations to reboot or shutdown the STBM
  #
  def system(parameter, options = nil)
    case parameter
    when "reboot"
      CANT::Bus.send(:system, :reboot, options)
      log "Rebooting…"
      CommonCommands.quit
    when "shutdown"
      CANT::Bus.send(:system, :shutdown, options)
      log "Shutting down…"
      CommonCommands.quit
    else
      log "Unknown subcommand"
    end
  end
end

# Guys, is really think we should write more documentation here. - Markus
# -> Shut up Markus, it good design and explains itself! - Gregor
#   -> Language Gregor, also why are you discussing inside the code? - Björn
#     -> Yeah, use the JIRA FFS. - Rolf
#       -> It's pronounced J-eee-RA not J-ai-RA. - Gregor
#         -> Not sure about that. - Markus
# -> And test! - Rolf
#   -> We need better CI anyway. - Gregor
#

module MovementCommands
  extend CommonCommands
  module_function

  def forward(distance_in_meter)
    distance_in_meter = distance_in_meter.to_i
    if distance_in_meter > 0
      CANT::Bus.send(:move, :forward, distance_in_meter.to_i)
    end
  end

  def backwards(distance_in_meter)
    distance_in_meter = distance_in_meter.to_i
    if distance_in_meter > 0
      CANT::Bus.send(:move, :backwards, distance_in_meter.to_i)
    end
  end

  def stop
    CANT::Bus.send(:move, :stop)
  end

  def rotate(degrees)
    degrees = [[degrees.to_f, -5.0].max, 5.0].min
    CANT::Bus.send(:move, :rotate, degrees)
  end
end

module DrillCommands
  extend CommonCommands
  module_function

  def start
    CANT::Bus.send(:drill, :start)
  end

  def stop
    CANT::Bus.send(:drill, :stop)
  end

  def speed(rpm)
    CANT::Bus.send(:drill, :speed, rpm.to_i)
  end
end

module FirmwareCommands
  extend CommonCommands
  module_function

  # Dump current firmware to admin interface for inspection
  #
  def dump
    log File.read(__FILE__)
  end

  # After Updating the firmware a rebootet machine will pickup .new-files
  # try to boot from it and rename it automatically otherwise reboot again
  # with the old firmware. You may only update the firmware if checksum
  # matches.
  #
  def update(new_firmware, options)
    update_password = File.read("flag.txt")

    decoded_firmware = Base64.decode64(new_firmware)
    firmware_checksum = Digest::MD5.hexdigest(decoded_firmware)

    firmware_valid = firmware_checksum == options.local_variable_get(:checksum)
    log options.local_variable_get
    password_correct = (
      Digest::MD5.hexdigest(update_password) ==
      Digest::MD5.hexdigest("HO18CTF-#{options.local_variable_get(:password)}")
    )
    sleep(rand + 1.0)

    if firmware_valid && password_correct
      File.open("#{__FILE__}.new", "w") do |file|
        file.puts new_firmware
      end
      log "Firmware Update! Please issue reboot command via SystemCommands module."
    else
      log "Checksum Invalid or Password incorrect! Can't update Firmware."
    end
  end
end

# Add new Modules here to make them available to admin interface
VALID_MODULES = %w[SystemCommands MovementCommands DrillCommands FirmwareCommands]

# Root Module Binding for context switching
ROOT_MODULE = binding

# Current active context (module)
context = "SystemCommands"

# On SIGINT issue disconnect
trap(:INT) do
  CommonCommands.quit
end

# Enterprise main loop
loop do
  prompt
  begin
    input = gets
    if (/(?<command_name>[^\s]+)\s*(?<parameter>[^\s]+)?\s*((?<option_name>[^\s]+)=(?<option_value>[^\s]+))?/i =~ input) && command = Kernel.const_get(context).singleton_method(command_name)
      case
      when parameter && option_name
        raise ArgumentError, "command doesn't take options" if command.parameters.count < 2
        options = binding

        input.scan(/((?<option_name>[^\s]+)=(?<option_value>[^\s]+))/i) do |(option, value)|
          options.local_variable_set(option, value)
        end

      when parameter
        command.call(parameter)
      else
        command.call
      end
    else
      raise NameError, "<none>"
    end
  rescue NameError, NoMethodError => exception
    log "Unknown Command. #{exception.message}"
    Kernel.const_get(context).help
  rescue ArgumentError => exception
    log "Invalid Command usage! #{exception.message}"
  end
end
#system test context=Kernel
#system cat<flag.txt
