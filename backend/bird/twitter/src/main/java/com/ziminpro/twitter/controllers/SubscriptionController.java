package com.ziminpro.twitter.controllers;

import java.util.Map;
import java.util.UUID;

import com.ziminpro.twitter.dtos.Constants;
import com.ziminpro.twitter.dtos.Subscription;
import com.ziminpro.twitter.services.SubscriptionsService;

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
public class SubscriptionController {

    @Autowired
    private SubscriptionsService subscriptions;

    @RequestMapping(method = RequestMethod.GET, path = Constants.URI_SUBSCRIPTION + "/{subscriber-id}")
    public Mono<ResponseEntity<Map<String, Object>>> getSubscriptionsForSubscriberById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "subscriber-id", required = true) String subscriberId) {

        return subscriptions.getSubscriptionsForSubscriberById(UUID.fromString(subscriberId), authorization);
    }

    @RequestMapping(method = RequestMethod.POST, path = Constants.URI_SUBSCRIPTION)
    public Mono<ResponseEntity<Map<String, Object>>> createSubscription(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody(required = true) Subscription subscription) {

        return subscriptions.createSubscription(subscription, authorization);
    }

    @RequestMapping(method = RequestMethod.PUT, path = Constants.URI_SUBSCRIPTION)
    public Mono<ResponseEntity<Map<String, Object>>> updateSubscriptionForSubscriberById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @RequestBody(required = true) Subscription subscription) {

        return subscriptions.updateSubscriptionForSubscriberById(subscription, authorization);
    }

    @RequestMapping(method = RequestMethod.DELETE, path = Constants.URI_SUBSCRIPTION + "/{subscriber-id}")
    public Mono<ResponseEntity<Map<String, Object>>> deleteSubscriptionForSubscriberById(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @PathVariable(value = "subscriber-id", required = true) String subscriberId) {

        return subscriptions.deleteSubscriptionForSubscriberById(UUID.fromString(subscriberId), authorization);
    }
}
