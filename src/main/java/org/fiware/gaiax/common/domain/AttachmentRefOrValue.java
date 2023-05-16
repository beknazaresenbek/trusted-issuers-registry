package org.fiware.gaiax.common.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;

import java.net.URI;
import java.net.URL;

//TODO: Make sense of this.
@EqualsAndHashCode(callSuper = true)
@Data
public class AttachmentRefOrValue extends Entity {

    private URI id;
    private URI href;
    private String attachmentType;
    private String content;
    private String description;
    private String mimeType;
    private URL url;
    private Quantity size;
    private TimePeriod validFor;
    private String name;
    private String atReferredType;
}
