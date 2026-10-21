//
// Created by Dmitri on 2026-09-13.
//

#include "EPA.h"

#include <__float_float.h>
#include <glm/geometric.hpp>

#include "GJK.h"


std::pair<std::vector<glm::vec4>, size_t> EPA::GetNormal(std::vector<glm::vec3> &polytope, std::vector<size_t> indices) {
    std::vector<glm::vec4> normals;
    size_t min = 0;
    float min_dst = 10000000000.0f;

    for (int i = 0; i < indices.size()/3; i++) {

        glm::vec3 A = polytope[indices[3*i]];
        glm::vec3 B = polytope[indices[3*i+1]];
        glm::vec3 C = polytope[indices[3*i+2]];

        glm::vec3 normal = glm::cross(B - A, C - A);
        float len = glm::length(normal);
        if (len < 1e-6f) {
            continue;
        }

        normal = glm::normalize(normal);
        float dst = dot(normal, A);

        if (dst < 0) {
            normal = -normal;
            dst = -dst;
        }

        normals.emplace_back(normal, dst);
        if (dst < min_dst) {
            min = i;
            min_dst = dst;
        }
    }

    return {normals, min};
}

void EPA::AddUnique(std::vector<std::pair<size_t, size_t> > &edges, const std::vector<size_t> &faces, size_t A, size_t B) {

    auto reverse = std::find_if(edges.begin(), edges.end(), [&](const std::pair<size_t, size_t>& edge) {
        return edge.first == faces[B] && edge.second == faces[A];
    });

    if (reverse != edges.end()) {
        edges.erase(reverse);
    }
    else {
        edges.emplace_back(faces[A], faces[B]);
    }
}

Collision EPA::ApplyEPA(Simplex &simplex, std::vector<Vertex> vA, std::vector<Vertex> vB) {

    Collision collisionInfo{};
    collisionInfo.normal = glm::vec3(0.0f);
    collisionInfo.depth = 0.0f;
    collisionInfo.collided = false;

    if (simplex.Size() < 4) return collisionInfo;

    std::vector<glm::vec3> polytope(simplex.begin(), simplex.end());
    std::vector<size_t> indices = {
        0, 1, 2,    0, 3, 1,
        0, 2, 3,    1, 3, 2
    };

    auto [normals, minTriangles] = GetNormal(polytope, indices);
    glm::vec3 min;
    float min_dst = 10000000000.0f;

    //glm::vec3 support = GJK::Support()

    return collisionInfo;
}