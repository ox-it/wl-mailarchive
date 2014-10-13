package org.sakaiproject.mailarchive;

import org.sakaiproject.tool.api.SessionManager;
import org.sakaiproject.user.api.PreferencesService;
import org.sakaiproject.util.ResourceLoader;

/**
 * A ResourceLoader that doesn't
 */
public class TestResourceLoader extends ResourceLoader {

    private final SessionManager sessionManager;
    private final PreferencesService preferencesServices;

    public TestResourceLoader(SessionManager sessionManager, PreferencesService preferencesService) {
        this.sessionManager = sessionManager;
        this.preferencesServices = preferencesService;
    }

    @Override
    protected SessionManager getSessionManager() {
        return sessionManager;
    }

    @Override
    protected PreferencesService getPreferencesService() {
        return preferencesServices;
    }

}
