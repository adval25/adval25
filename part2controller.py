from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    
    fm_icmp = of.ofp_flow_mod()
    fm_icmp.match = of.ofp_match()
    fm_icmp.match.dl_type = 0x800
    fm_icmp.priority = 0xFFFF
    fm_icmp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    connection.send(fm_icmp)
    
    fm_arp = of.ofp_flow_mod()
    fm_arp.match = of.ofp_match()
    fm_arp.match.dl_type = 0x806
    fm_arp.priority = 0x8000
    fm_arp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    connection.send(fm_arp)
    
    fm = of.ofp_flow_mod()
    fm.match = of.ofp_match()
    fm.match.dl_type = 0x800
    fm.priority = 0
    fm.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    connection.send(fm)
    

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet :" + str(packet.dump()))


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
