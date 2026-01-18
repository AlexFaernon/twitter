package com.ziminpro.twitter.controllers;

import java.util.Map;
import java.util.UUID;

import com.ziminpro.twitter.dtos.Constants;
import com.ziminpro.twitter.dtos.Message;
import com.ziminpro.twitter.services.MessagesService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class MessageController {

    @Autowired
    private MessagesService messages;

    @RequestMapping(method = RequestMethod.GET, path = Constants.URI_MESSAGE + "/{message-id}")
    public Mono<ResponseEntity<Map<String, Object>>> getMessagebyId(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "message-id", required = true) String messageId) {

        return messages.getMessagebyId(UUID.fromString(messageId), authorization);
    }

    @RequestMapping(method = RequestMethod.GET, path = Constants.URI_MESSAGE + "/producer/{producer-id}")
    public Mono<ResponseEntity<Map<String, Object>>> getMessagesForProducerById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "producer-id", required = true) String producerId) {

        return messages.getMessagesForProducerById(UUID.fromString(producerId), authorization);
    }

    @RequestMapping(method = RequestMethod.GET, path = Constants.URI_MESSAGE + "/subscriber/{subscriber-id}")
    public Mono<ResponseEntity<Map<String, Object>>> getMessagesForSubscriberById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "subscriber-id", required = true) String subscriberId) {

        return messages.getMessagesForSubscriberById(UUID.fromString(subscriberId), authorization);
    }

    @RequestMapping(method = RequestMethod.POST, path = Constants.URI_MESSAGE)
    public Mono<ResponseEntity<Map<String, Object>>> createMessage(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody(required = true) Message message) {

        return messages.createMessage(message, authorization);
    }

    @RequestMapping(method = RequestMethod.DELETE, path = Constants.URI_MESSAGE + "/{message-id}")
    public Mono<ResponseEntity<Map<String, Object>>> deleteMessageById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "message-id", required = true) String messageId) {

        return messages.deleteMessageById(UUID.fromString(messageId), authorization);
    }
}