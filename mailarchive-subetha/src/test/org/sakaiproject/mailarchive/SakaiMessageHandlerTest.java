package org.sakaiproject.mailarchive;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.sakaiproject.alias.api.AliasService;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.content.api.ContentHostingService;
import org.sakaiproject.entity.api.EntityManager;
import org.sakaiproject.entity.api.Reference;
import org.sakaiproject.exception.IdUnusedException;
import org.sakaiproject.mailarchive.api.MailArchiveChannel;
import org.sakaiproject.mailarchive.api.MailArchiveService;
import org.sakaiproject.site.api.SiteService;
import org.sakaiproject.thread_local.api.ThreadLocalManager;
import org.sakaiproject.time.api.Time;
import org.sakaiproject.time.api.TimeService;
import org.sakaiproject.user.api.UserDirectoryService;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.sql.Ref;
import java.util.List;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Created by buckett on 06/10/2014.
 */
public class SakaiMessageHandlerTest {

    private SakaiMessageHandlerFactory factory;

    @Mock
    private ServerConfigurationService serverConfigurationService;

    @Mock
    private EntityManager entityManager;

    @Mock
    private AliasService aliasService;

    @Mock
    private UserDirectoryService userDirectoryService;

    @Mock
    private SiteService siteService;

    @Mock
    private TimeService timeService;

    @Mock
    private ThreadLocalManager threadLocalManager;

    @Mock
    private ContentHostingService contentHostingService;

    @Mock
    private MailArchiveService mailArchiveService;

    private Properties props;

    @Before
    public void setUp() {
        initMocks(this);
        factory = new SakaiMessageHandlerFactory();
        factory.setServerConfigurationService(serverConfigurationService);
        factory.setEntityManager(entityManager);
        factory.setAliasService(aliasService);
        factory.setUserDirectoryService(userDirectoryService);
        factory.setSiteService(siteService);
        factory.setTimeService(timeService);
        factory.setThreadLocalManager(threadLocalManager);
        factory.setContentHostingService(contentHostingService);
        factory.setMailArchiveService(mailArchiveService);

        when(serverConfigurationService.getBoolean("smtp.enabled", false)).thenReturn(true);
        when(serverConfigurationService.getServerName()).thenReturn("example.com");
        when(serverConfigurationService.getString("sakai.version", "unknown")).thenReturn("test");
        // Pick a random unused port.
        when(serverConfigurationService.getInt("smtp.port", 25)).thenReturn(0);

        factory.init();
        props = new Properties();
        props.put("mail.smtp.host", "localhost");
        props.put("mail.smtp.port", factory.getPort());
    }

    @After
    public void tearDown() {
        factory.destroy();
    }

    @Test
    public void testStartStop() {
    }

    @Test
    public void testReceiveMail() throws Exception {

        when(aliasService.getTarget("archive")).thenReturn("/site/siteId");

        Reference ref = mock(Reference.class);
        when(ref.getType()).thenReturn(SiteService.APPLICATION_ID);
        when(ref.getId()).thenReturn("siteId");
        when(entityManager.newReference("/site/siteId")).thenReturn(ref);

        when(mailArchiveService.channelReference("siteId", SiteService.MAIN_CONTAINER)).thenReturn("/mailarchive/channel/siteId/main");

        MailArchiveChannel channel = mock(MailArchiveChannel.class);
        when(channel.getEnabled()).thenReturn(true);
        when(channel.getOpen()).thenReturn(true);
        when(channel.getContext()).thenReturn("siteId");

        when(mailArchiveService.getMailArchiveChannel("/mailarchive/channel/siteId/main")).thenReturn(channel);

        when (siteService.siteExists("siteId")).thenReturn(true);

        Session session = Session.getDefaultInstance(props);
        Message msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress("from@somewhere.com"));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress("archive@example.com"));
        msg.setSubject("Subject");
        msg.setText("Just a test");
        Transport transport = session.getTransport("smtp");
        transport.connect();
        transport.sendMessage(msg, msg.getAllRecipients());
        transport.close();

        verify(channel).addMailArchiveMessage(eq("Subject"), eq("from@somewhere.com"), any(Time.class), any(List.class), any(List.class), any(String[].class));
    }
}
