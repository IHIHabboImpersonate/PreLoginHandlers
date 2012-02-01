#region GPLv3

// 
// Copyright (C) 2012  Chris Chenery
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 

#endregion

#region Usings

using System.Collections.Generic;
using IHI.Server.Habbos;
using IHI.Server.Networking;
using IHI.Server.Networking.Messages;

#endregion

namespace IHI.Server.Plugins.Cecer1.PreLoginHandlers
{
    [CompatibilityLock(36)]
    public class LoginHandlers : Plugin
    {
        public override void Start()
        {
            Core serverCore = CoreManager.ServerCore;

            serverCore.GetConnectionManager().OnConnectionOpen += RegisterHandlers;
            serverCore.GetHabboDistributor().OnPreHabboLogin += SendPermissions;
            serverCore.GetHabboDistributor().OnHabboLogin += SendAuthenticationOkay;
        }


        private static void RegisterHandlers(object source, ConnectionEventArgs args)

        {
            IonTcpConnection connection = source as IonTcpConnection;

            if (connection == null)
                return;

            connection.
                AddHandler(2002, PacketHandlerPriority.DefaultAction, ProcessSessionRequest).
                AddHandler(206, PacketHandlerPriority.DefaultAction, ProcessEncryptionRequest).
                AddHandler(204, PacketHandlerPriority.DefaultAction, ProcessSSOTicket);
        }

        public void UnregisterHandlers(Habbo target)
        {
            UnregisterHandlers(target.GetConnection());
        }

        private static void UnregisterHandlers(IonTcpConnection connection)
        {
            connection
                .AddHandler(206, PacketHandlerPriority.DefaultAction, ProcessEncryptionRequest)
                .AddHandler(204, PacketHandlerPriority.DefaultAction, ProcessSSOTicket)
                .AddHandler(2002, PacketHandlerPriority.DefaultAction, ProcessSessionRequest);
        }

        private static void ProcessEncryptionRequest(Habbo sender, IncomingMessage message)
        {
            new MSetupEncryption
                {
                    UnknownA = false
                }.Send(sender);
        }

        private static void ProcessSessionRequest(Habbo sender, IncomingMessage message)
        {
            new MSessionParams
                {
                    A = 9,
                    B = 0,
                    C = 0,
                    D = 1,
                    E = 1,
                    F = 3,
                    G = 0,
                    H = 2,
                    I = 1,
                    J = 4,
                    K = 0,
                    L = 5,
                    DateFormat = "dd-MM-yyyy",
                    M = "",
                    N = 7,
                    O = false,
                    P = 8,
                    URL = "http://ihi.cecer1.com",
                    Q = "",
                    R = 9,
                    S = false
                }.Send(sender);
        }

        private static void ProcessSSOTicket(Habbo sender, IncomingMessage message)
        {
            Habbo loggedInHabbo = CoreManager.ServerCore.GetHabboDistributor().GetHabbo(
                message.PopPrefixedString(), sender.GetConnection().GetIPAddressRaw());

            if (loggedInHabbo == null)
            {
                new MConnectionClosed
                    {
                        Reason = ConnectionClosedReason.InvalidSSOTicket
                    }.Send(sender);

                // TODO: Is delay needed?

                sender.GetConnection().Disconnect(); // Invalid SSO Ticket
            }
            else
            {
                // If this Habbo is already connected...
                if (loggedInHabbo.IsLoggedIn())
                {
                    // Disconnect them.
                    new MConnectionClosed
                        {
                            Reason = ConnectionClosedReason.ConcurrentLogin
                        }.Send(loggedInHabbo);
                    loggedInHabbo.GetConnection().Disconnect();
                }
                loggedInHabbo.LoginMerge(sender);
                sender = loggedInHabbo;
                sender.SetLoggedIn(true);
            }
        }

        private static void SendPermissions(object source, HabboEventArgs habboEventArgs)
        {
            // Get the fuse permissions.
            IEnumerable<string> fusePermissions = (source as Habbo).GetFusePermissions();

            // Send them to the client.
            new MPermissions
                {
                    FuseRights = fusePermissions
                }.Send((source as Habbo));


            // Mark them as sent.
            (source as Habbo).SetFusePermissionSent(fusePermissions);
        }

        private static void SendAuthenticationOkay(object source, HabboEventArgs e)
        {
            // Inform the client of a successful login.
            new MAuthenticationOkay().Send(source as IMessageable);
        }
    }
}