using IHI.Server.Habbos;
using IHI.Server.Networking;
using IHI.Server.Networking.Messages;

namespace IHI.Server.Plugins.Cecer1.PreLoginHandlers
{
    public class PreLoginHandlers : Plugin
    {
        public override void Start()
        {
            CoreManager.GetServerCore().GetConnectionManager().OnConnectionOpen += RegisterHandlers;
        }


        private static void RegisterHandlers(object source, ConnectionEventArgs args)

        {
            var connection = source as IonTcpConnection;

            if (connection == null)
                return;
            
            connection.
                AddHandler(206, PacketHandlerPriority.DefaultAction, ProcessSessionRequest).
                AddHandler(415, PacketHandlerPriority.DefaultAction, ProcessSSOTicket);
        }

        public void UnregisterHandlers(Habbo target)
        {
            UnregisterHandlers(target.GetConnection());
        }

        private static void UnregisterHandlers(IonTcpConnection connection)
        {
            connection
                .AddHandler(206, PacketHandlerPriority.DefaultAction, ProcessSessionRequest)
                .AddHandler(415, PacketHandlerPriority.DefaultAction, ProcessSSOTicket);
        }

        private static void ProcessSessionRequest(Habbo sender, IncomingMessage message)
        {
            new MSessionParams(9, 0, 0, 1, 1, 3, 0, 2, 0, 4, 1, 5, "dd-MM-yyyy", 7, 0, 8, "http://ihi.cecer1.com", 9, 0)
                .Send(sender);
        }

        private static void ProcessSSOTicket(Habbo sender, IncomingMessage message)
        {
            var loggedInUser = CoreManager.GetServerCore().GetHabboDistributor().GetHabbo(
                message.PopPrefixedString(), sender.GetConnection().GetIPAddressRaw());

            if (loggedInUser == null)
            {
                new MConnectionClosed(ConnectionClosedReason.InvalidSSOTicket)
                    .Send(sender);

                // TODO: Is delay needed?

                sender.GetConnection().Disconnect(); // Invalid SSO Ticket
            }
            else
            {
                if (loggedInUser.IsLoggedIn())
                {
                    // TODO: Disconnect reason
                    //Sender.GetPacketSender().Send_ConnectionClosed(ConnectionClosedReason.ConcurrentLogin);
                    loggedInUser.GetConnection().Disconnect();
                }
                loggedInUser.LoginMerge(sender);
                sender = loggedInUser;
                sender.SetLoggedIn(true);

                //Sender.GetPacketSender().Send_FuseRights(Sender.GetFuserights());

                new MAuthenticationOkay().Send(sender);
            }
        }
    }
}