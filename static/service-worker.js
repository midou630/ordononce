const CACHE_NAME = "arbicorp-v2";

const FILES_TO_CACHE = [

    "/",
    "/dashboard",
    "/Prescription",
    "/analyses",

    "/static/manifest.json",
    "/static/service-worker.js",

    "/static/assets/data/medications.json",
    "/static/assets/data/analyses.json",

    "/static/assets/templates/prescription-template.png",
    "/static/assets/templates/analysis-template.png"

];

self.addEventListener("install", event => {

    event.waitUntil(

        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(FILES_TO_CACHE))

    );

});

self.addEventListener("activate", event => {

    event.waitUntil(

        caches.keys().then(keys => {

            return Promise.all(

                keys.map(key => {

                    if (key !== CACHE_NAME) {

                        return caches.delete(key);

                    }

                })

            );

        })

    );

});

self.addEventListener("fetch", event => {

    event.respondWith(

        caches.match(event.request).then(response => {

            if (response) {

                return response;

            }

            return fetch(event.request).then(networkResponse => {

                if (
                    event.request.method === "GET"
                ) {

                    const copy = networkResponse.clone();

                    caches.open(CACHE_NAME).then(cache => {

                        cache.put(event.request, copy);

                    });

                }

                return networkResponse;

            });

        })

    );

});