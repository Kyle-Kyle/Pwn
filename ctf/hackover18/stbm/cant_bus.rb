# You really shouldn't need to be here.
#

module CANT
  module Bus
    module_function
    def send(target, command, payload=nil)
      # Did you really think this would be proper code?
      # just a dummy
      case payload
      when NilClass
        puts "[!] #{target.upcase} #{command}"
      when Binding
        puts "[!] #{target.upcase} #{command} > #{payload.local_variables.join(" ")}"
      else
        puts "[!] #{target.upcase} #{command} > #{payload}"
      end
    end
  end
end
