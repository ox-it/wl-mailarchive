package org.sakaiproject.mailarchive;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.sakaiproject.alias.api.AliasService;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.content.api.ContentHostingService;
import org.sakaiproject.entity.api.EntityManager;
import org.sakaiproject.entity.api.Reference;
import org.sakaiproject.exception.IdUnusedException;
import org.sakaiproject.exception.PermissionException;
import org.sakaiproject.i18n.InternationalizedMessages;
import org.sakaiproject.mailarchive.api.MailArchiveChannel;
import org.sakaiproject.mailarchive.api.MailArchiveService;
import org.sakaiproject.site.api.SiteService;
import org.sakaiproject.thread_local.api.ThreadLocalManager;
import org.sakaiproject.time.api.Time;
import org.sakaiproject.time.api.TimeService;
import org.sakaiproject.tool.api.SessionManager;
import org.sakaiproject.user.api.PreferencesService;
import org.sakaiproject.user.api.UserDirectoryService;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.util.*;

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

    @Mock
    private SessionManager sessionManager;

    @Mock
    private PreferencesService preferencesService;

    private InternationalizedMessages i18nMessages;

    private Properties props;

    @Before
    public void setUp() {
        initMocks(this);

        i18nMessages = new TestResourceLoader(sessionManager, preferencesService);

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
        factory.setMessages(i18nMessages);


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
        mockSite("siteId");
        mockAlias("siteId", "archive");
        MailArchiveChannel channel = mockChannel("siteId", SiteService.MAIN_CONTAINER);
        sendMessage("from@somewhere.com", "archive@example.com", "Subject", "Just a test");

        verify(channel).addMailArchiveMessage(eq("Subject"), eq("from@somewhere.com"), any(Time.class), any(List.class), any(List.class), any(String[].class));
        verify(threadLocalManager).clear();
    }


    @Test
    public void testNoReplyMail() throws Exception {
        // This should just get swallowed.
        sendMessage("from@somewhere.com", "no-reply@example.com", "Subject", "Just a test");
    }

    @Test
    public void testToDisabled() throws Exception {
        mockSite("siteId");
        mockAlias("siteId", "archive");
        MailArchiveChannel channel = mockChannel("siteId", SiteService.MAIN_CONTAINER);
        when(channel.getEnabled()).thenReturn(false);

        sendMessage("from@somewhere.com", "archive@example.com", "Subject", "Just a test");

    }

    @Test(expected = SendFailedException.class)
    public void testRejectWrongDomain() throws Exception {
        // This is a domain we're not handling.
        sendMessage("from@somewhere.com", "local@otherdomain.com", "Subject", "Just a test");
    }


    protected void mockAlias(String siteId, String alias) throws IdUnusedException {
        when(aliasService.getTarget(alias)).thenReturn("/site/"+ siteId);
    }

    protected MailArchiveChannel mockChannel(String siteId, String container) throws IdUnusedException, PermissionException {
        MailArchiveChannel channel = mock(MailArchiveChannel.class);
        when(channel.getEnabled()).thenReturn(true);
        when(channel.getOpen()).thenReturn(true);
        when(channel.getContext()).thenReturn(siteId);
        when(mailArchiveService.getMailArchiveChannel("/mailarchive/channel/"+ siteId + "/"+ container)).thenReturn(channel);
        when(mailArchiveService.channelReference(siteId, container)).thenReturn("/mailarchive/channel/"+ siteId + "/"+ container);
        return channel;
    }

    protected void mockSite(String siteId) {
        Reference ref = mock(Reference.class);
        when(ref.getType()).thenReturn(SiteService.APPLICATION_ID);
        when(ref.getId()).thenReturn(siteId);
        when(entityManager.newReference("/site/" + siteId)).thenReturn(ref);
        when(siteService.siteExists(siteId)).thenReturn(true);
    }

    protected void sendMessage(String from, String to, String subject, String body) throws MessagingException {
        Session session = Session.getInstance(props);
        Message msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject(subject);
        msg.setText(body);
        Transport transport = session.getTransport("smtp");
        transport.connect();
        transport.sendMessage(msg, msg.getAllRecipients());
        transport.close();
    }

}
